import * as oauth from 'oauth4webapi';
import { URL } from 'url';
import { OAuthClientDb, ClientCredentials, PKCEValues } from './oauthClientDb';
import { FetchLike } from './types';

export class OAuthAuthenticationRequiredError extends Error {
  constructor(
    public readonly state: string,
    public readonly resourceServerUrl: string,
    public readonly authorizationUrl: URL
  ) {
    super('OAuth authentication required');
    this.name = 'OAuthAuthenticationRequiredError';
  }
}

export class OAuthClient implements FetchLike {
  private db: OAuthClientDb;
  private allowInsecureRequests = process.env.NODE_ENV === 'development';
  private callbackUrl: string;
  // Whether this is a public client, which is incapable of keeping a client secret
  // safe, or a confidential client, which can.
  private isPublic: boolean;

  constructor(db: OAuthClientDb, callbackUrl: string, isPublic: boolean) {
    this.db = db;
    this.callbackUrl = callbackUrl;
    this.isPublic = isPublic;
  }

  private getAuthorizationServer = async (resourceServerUrl: string): Promise<oauth.AuthorizationServer> => {
    console.log(`Fetching authorization server configuration for ${resourceServerUrl}`);
    
    try {
      const resourceUrl = new URL(resourceServerUrl);
      const prmResponse = await oauth.resourceDiscoveryRequest(resourceUrl, {
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      });
      const resourceServer = await oauth.processResourceDiscoveryResponse(resourceUrl, prmResponse);
      const authServerUrl = resourceServer.authorization_servers?.[0];
      if (!authServerUrl) {
        throw new Error('No authorization_servers found in protected resource metadata');
      }

      console.log(`Found authorization server URL: ${authServerUrl}`);
      
      // Now, get the authorization server metadata
      const issuer = new URL(authServerUrl);
      const response = await oauth.discoveryRequest(issuer, {
        algorithm: 'oauth2',
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      });
      const authorizationServer = await oauth.processDiscoveryResponse(issuer, response);
      
      console.log(`Retrieved authorization server configuration for ${resourceServerUrl}`);
      return authorizationServer;
    } catch (error: any) {
      console.log(`Error fetching authorization server configuration: ${error}`);
      throw error;
    }
  }

  private registerClient = async (
    authorizationServer: oauth.AuthorizationServer,
    resourceServerUrl: string
  ): Promise<ClientCredentials> => {
    console.log(`Registering client with authorization server for ${resourceServerUrl}`);
    
    if (!authorizationServer.registration_endpoint) {
      throw new Error('Authorization server does not support dynamic client registration');
    }

    let grantTypes = ['authorization_code', 'refresh_token'];
    if (!this.isPublic) {
      grantTypes.push('client_credentials');
    }

    let tokenEndpointAuthMethod = 'none';
    if (!this.isPublic) {
      tokenEndpointAuthMethod = 'client_secret_post';
    }
    
    // Create client metadata for registration
    const clientMetadata: Partial<oauth.Client> = {
      // Required fields for public client
      redirect_uris: [this.callbackUrl], 
      response_types: ['code'], 
      grant_types: grantTypes,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      client_name: `OAuth Client for ${resourceServerUrl}`,
    };
    
    // Make the registration request
    const response = await oauth.dynamicClientRegistrationRequest(
      authorizationServer,
      clientMetadata,
      {
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      }
    );

    // Process the registration response
    const registeredClient = await oauth.processDynamicClientRegistrationResponse(response);
    
    console.log(`Successfully registered client with ID: ${registeredClient.client_id}`);
    
    // Create client credentials from the registration response
    const credentials: ClientCredentials = {
      clientId: registeredClient.client_id,
      clientSecret: registeredClient.client_secret?.toString() || '', // Public client has no secret
      redirectUri: this.callbackUrl
    };
    
    // Save the credentials in the database
    await this.db.saveClientCredentials(resourceServerUrl, credentials);
    
    return credentials;
  }

  private generatePKCE = async (resourceServerUrl: string): Promise<{
    codeVerifier: string;
    codeChallenge: string;
    state: string;
  }> => {
    console.log('Generating PKCE values');
    
    // Generate a random code verifier
    const codeVerifier = oauth.generateRandomCodeVerifier();
    
    // Calculate the code challenge
    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier);
    
    // Generate a random state
    const state = oauth.generateRandomState();
    
    // Save the PKCE values in the database
    await this.db.savePKCEValues(state, {
      codeVerifier,
      codeChallenge,
      resourceServerUrl
    });
    
    console.log(`Generated PKCE values with state: ${state}`);
    return { codeVerifier, codeChallenge, state };
  }

  private getAuthorizeUrl = async (
    authorizationServer: oauth.AuthorizationServer, 
    credentials: ClientCredentials, 
    codeChallenge: string, 
    state: string
  ): Promise<URL> => {
    // Create the authorization URL
    const authorizationUrl = new URL(authorizationServer.authorization_endpoint || '');
    authorizationUrl.searchParams.set('client_id', credentials.clientId);
    authorizationUrl.searchParams.set('redirect_uri', credentials.redirectUri);
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('code_challenge', codeChallenge);
    authorizationUrl.searchParams.set('code_challenge_method', 'S256');
    authorizationUrl.searchParams.set('state', state);
    return authorizationUrl;
  }

  private requestAuthorization = async (resourceServerUrl: string): Promise<string> => {
    console.log(`Requesting authorization for ${resourceServerUrl}`);
    
    // Get the authorization server configuration
    const authorizationServer = await this.getAuthorizationServer(resourceServerUrl);
    
    // Get the client credentials
    let credentials = await this.db.getClientCredentials(resourceServerUrl);
    
    // If no credentials found, register a new client
    if (!credentials) {
      console.log(`No client credentials found for ${resourceServerUrl}, attempting dynamic client registration`);
      credentials = await this.registerClient(authorizationServer, resourceServerUrl);
    }
    
    // Generate PKCE values
    const { codeChallenge, state } = await this.generatePKCE(resourceServerUrl);
    
    // Create the authorization URL
    const authorizationUrl = await this.getAuthorizeUrl(
      authorizationServer,
      credentials,
      codeChallenge,
      state
    );
    
    // Throw error with the authorization URL
    throw new OAuthAuthenticationRequiredError(state, resourceServerUrl, authorizationUrl);
  }

  private exchangeCodeForToken = async (
    authResponse: URLSearchParams,
    state: string,
    pkceValues: PKCEValues,
    authorizationServer: oauth.AuthorizationServer
  ): Promise<string> => {
    console.log(`Exchanging code for tokens with state: ${state}`);
    
    const { codeVerifier, resourceServerUrl } = pkceValues;
    
    // Get the client credentials
    const credentials = await this.db.getClientCredentials(resourceServerUrl);
    if (!credentials) {
      throw new Error(`No client credentials found for ${resourceServerUrl}`);
    }
    
    // Create the client configuration
    const client: oauth.Client = { 
      client_id: credentials.clientId,
      token_endpoint_auth_method: 'none'
    };
    let clientAuth = oauth.None();
    
    // If the client has a secret, that means it was registered as a confidential client
    // In that case, we should auth to the token endpoint using the client secret as well.
    // In either case (public or confidential), we're also using PKCE
    if (credentials.clientSecret) {
      client.token_endpoint_auth_method = 'client_secret_post';
      // Create the client authentication method
      clientAuth = oauth.ClientSecretPost(credentials.clientSecret);
    }
    
    // Make the token request
    const response = await oauth.authorizationCodeGrantRequest(
      authorizationServer,
      client,
      clientAuth,
      authResponse,
      credentials.redirectUri,
      codeVerifier, {
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      }
    );
    
    // Process the token response
    const result = await oauth.processAuthorizationCodeResponse(
      authorizationServer,
      client,
      response
    );
    
    // Save the access token in the database
    await this.db.saveAccessToken(resourceServerUrl, {
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      expiresAt: result.expires_in 
        ? new Date(Date.now() + result.expires_in * 1000) 
        : undefined
    });
    
    return result.access_token;
  }

  handleCallback = async (url: string): Promise<void> => {
    console.log(`Handling authorization code callback: ${url}`);

    const callbackUrl = new URL(url);
    const state = callbackUrl.searchParams.get('state');
    
    if (!state) {
      throw new Error('No state parameter found in callback URL');
    }
    
    // Get the PKCE values and resource server URL from the database using the state
    const pkceValues = await this.db.getPKCEValues(state);
    if (!pkceValues) {
      throw new Error(`No PKCE values found for state: ${state}`);
    }
    
    // Get the authorization server configuration
    const authorizationServer = await this.getAuthorizationServer(pkceValues.resourceServerUrl);

    // Get the client credentials
    const credentials = await this.db.getClientCredentials(pkceValues.resourceServerUrl);
    if (!credentials) {
      throw new Error(`No client credentials found for ${pkceValues.resourceServerUrl}`);
    }
    
    // Create the client configuration
    const client: oauth.Client = { 
      client_id: credentials.clientId,
      token_endpoint_auth_method: 'client_secret_post'
    };
    
    // Validate the authorization response
    const authResponse = await oauth.validateAuthResponse(
      authorizationServer,
      client,
      callbackUrl,
      state
    );

    // Exchange the code for tokens
    await this.exchangeCodeForToken(authResponse, state, pkceValues, authorizationServer);
  }

  static getResourceServerUrl = (url: string): string => {
    const urlObj = new URL(url);
    return `${urlObj.origin}${urlObj.pathname}`;
  }

  static getParentPath = (url: string): string | null => {
    const urlObj = new URL(url);
    urlObj.pathname = urlObj.pathname.replace(/\/[^/]+$/, '');
    const res = urlObj.toString();
    return res === url ? null : res;
  }

  fetch = async (
    url: string,
    init?: {
      method?: string;
      headers?: Record<string, string>;
      body?: any;
    }
  ): Promise<Response> => {
    console.log(`Making ${init?.method || 'GET'} request to ${url}`);
    
    // Get the access token from the database
    let resourceServerUrl = OAuthClient.getResourceServerUrl(url);
    let parentPath = OAuthClient.getParentPath(resourceServerUrl);
    let tokenData = await this.db.getAccessToken(resourceServerUrl);
    // If there's no token for the requested path, see if there's one for the parent
    while (!tokenData && parentPath){
      console.log(`No access token found for ${resourceServerUrl}, trying parent ${parentPath}`);
      resourceServerUrl = parentPath;
      tokenData = await this.db.getAccessToken(resourceServerUrl);
      parentPath = OAuthClient.getParentPath(resourceServerUrl);
    }
    if (!tokenData) {
      console.log(`No access token found for resource server ${resourceServerUrl}. Passing no authorization header.`);
    }
    const headers = init?.headers || {};
    
    if (tokenData) {
      headers['Authorization'] = `Bearer ${tokenData.accessToken}`;
    }
    
    // Make the request with the access token
    try {
      const response = await fetch(url, {
        method: init?.method || 'GET',
        headers,
        body: init?.body
      });
      
      if (!response.ok) {
        // If we get a 401 Unauthorized error, the access token might be invalid
        if (response.status === 401) {
          console.log('Received 401 Unauthorized error, initiating OAuth flow');
          
          // Request authorization and throw specific error
          // This will do some requests to get the authorization url 
          // and then throw and error containing it
          await this.requestAuthorization(resourceServerUrl);
        }
        
        // For other errors, throw a standard error
        throw new Error(`Request failed: ${response.status} ${response.statusText}`);
      }
      
      return response;
    } catch (error: any) {
      // If it's already an OAuthAuthenticationRequiredError, rethrow it
      if (error instanceof OAuthAuthenticationRequiredError) {
        throw error;
      }
      
      // If it's not a 401 error or an OAuth error, rethrow
      throw error;
    }
  }
}