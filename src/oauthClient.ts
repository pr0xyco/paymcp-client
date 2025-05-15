import * as oauth from 'oauth4webapi';
import { URL } from 'url';
import { FetchLike, OAuthClientDb, ClientCredentials, PKCEValues, TokenData, AccessToken } from './types';

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

export class OAuthClient {
  protected db: OAuthClientDb;
  protected allowInsecureRequests = process.env.NODE_ENV === 'development';
  protected callbackUrl: string;
  protected fetchFn: FetchLike;
  protected strict: boolean;
  // Whether this is a public client, which is incapable of keeping a client secret
  // safe, or a confidential client, which can.
  protected isPublic: boolean;

  constructor(db: OAuthClientDb, callbackUrl: string, isPublic: boolean, fetchFn: FetchLike = fetch, strict: boolean = true) {
    this.db = db;
    this.callbackUrl = callbackUrl;
    this.isPublic = isPublic;
    this.fetchFn = fetchFn;
    this.strict = strict;
  }

  fetch: FetchLike = async (url, init) => {
    const resourceServerUrl = OAuthClient.getResourceServerUrl(url);
    let response = await this._doFetch(url, init);
    
    if (response.status === 401) {
      console.log('Received 401 Unauthorized status');

      // If the response indicates an expired token, try to refresh it
      const wwwAuthenticate = response.headers.get('www-authenticate');
      if (wwwAuthenticate && wwwAuthenticate.includes('error="invalid_grant"')) {
        console.log('Response includes invalid_grant error, attempting to refresh token');
        const newToken = await this.tryRefreshToken(resourceServerUrl);
        if(newToken) {
          response = await this._doFetch(url, init);
        }
      }
    }

    if (response.status === 401) {
      console.log('Received 401 Unauthorized status, initiating OAuth flow');
      // Request authorization and throw specific error
      // This will do some requests to get the authorization url 
      // and then throw and error containing it
      await this.throwAuthorizationError(resourceServerUrl);
    }
  
    return response;
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
    const authServerUrl = await this.getAuthorizationServerUrl(pkceValues.resourceServerUrl);
    const authorizationServer = await this.getAuthorizationServer(authServerUrl);

    // Get the client credentials
    const credentials = await this.getClientCredentials(pkceValues.resourceServerUrl, authorizationServer);
    
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

  protected getAuthorizationServerUrl = async (resourceServerUrl: string): Promise<URL> => {
    console.log(`Fetching authorization server configuration for ${resourceServerUrl}`);
    
    try {
      let authServerUrl: string | undefined = undefined;
      const resourceUrl = new URL(resourceServerUrl);

      const prmResponse = await oauth.resourceDiscoveryRequest(resourceUrl, {
        [oauth.customFetch]: this.fetchFn,
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      });

      const fallbackToRsAs = !this.strict && prmResponse.status === 404;

      if (!fallbackToRsAs) {
        const resourceServer = await oauth.processResourceDiscoveryResponse(resourceUrl, prmResponse);
        authServerUrl = resourceServer.authorization_servers?.[0];
      } else {
        // Some older servers serve OAuth metadata from the MCP server instead of PRM data, 
        // so if the PRM data isn't found, we'll try to get the AS metadata from the MCP server
        console.log('Protected Resource Metadata document not found, looking for OAuth metadata on resource server');
        // Trim off the path - OAuth metadata is also singular for a server and served from the root
        const rsUrl = new URL(resourceServerUrl);
        const rsAsUrl = rsUrl.protocol + '//' + rsUrl.host + '/.well-known/oauth-authorization-server';
        // Don't use oauth4webapi for this, because these servers might be specifiying an issuer that is not
        // themselves (in order to use a separate AS by just hosting the OAuth metadata on the MCP server)
        //   This is against the OAuth spec, but some servers do it anyway
        const rsAsResponse = await this.fetchFn(rsAsUrl);
        if (rsAsResponse.status === 200) {
          const rsAsBody = await rsAsResponse.json();
          authServerUrl = rsAsBody.issuer;
        }
      }

      if (!authServerUrl) {
        throw new Error('No authorization_servers found in protected resource metadata');
      }

      console.log(`Found authorization server URL: ${authServerUrl}`);
      return new URL(authServerUrl);
    } catch (error: any) {
      console.log(`Error fetching authorization server configuration: ${error}`);
      throw error;
    }
  }
      
  protected getAuthorizationServer = async (authServerUrl: URL): Promise<oauth.AuthorizationServer> => {
    try {
      // Now, get the authorization server metadata
      const response = await oauth.discoveryRequest(authServerUrl, {
        algorithm: 'oauth2',
        [oauth.customFetch]: this.fetchFn,
        [oauth.allowInsecureRequests]: this.allowInsecureRequests,
      });
      const authorizationServer = await oauth.processDiscoveryResponse(authServerUrl, response);
      return authorizationServer;
    } catch (error: any) {
      console.log(`Error fetching authorization server configuration: ${error}`);
      throw error;
    }
  }

  protected getRegistrationMetadata = async (resourceServerUrl: string): Promise<Partial<oauth.OmitSymbolProperties<oauth.Client>>> => {
    let grantTypes = ['authorization_code', 'refresh_token'];
    if (!this.isPublic) {
      grantTypes.push('client_credentials');
    }

    let tokenEndpointAuthMethod = 'none';
    if (!this.isPublic) {
      tokenEndpointAuthMethod = 'client_secret_post';
    }
    
    // Create client metadata for registration
    const clientMetadata = {
      // Required fields for public client
      redirect_uris: [this.callbackUrl], 
      response_types: ['code'], 
      grant_types: grantTypes,
      token_endpoint_auth_method: tokenEndpointAuthMethod,
      client_name: `OAuth Client for ${resourceServerUrl}`,
    };
    return clientMetadata;
  }

  protected registerClient = async (
    authorizationServer: oauth.AuthorizationServer,
    resourceServerUrl: string
  ): Promise<ClientCredentials> => {
    console.log(`Registering client with authorization server for ${resourceServerUrl}`);
    
    if (!authorizationServer.registration_endpoint) {
      throw new Error('Authorization server does not support dynamic client registration');
    }

    const clientMetadata = await this.getRegistrationMetadata(resourceServerUrl);
    
    // Make the registration request
    const response = await oauth.dynamicClientRegistrationRequest(
      authorizationServer,
      clientMetadata,
      {
        [oauth.customFetch]: this.fetchFn,
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

  protected generatePKCE = async (resourceServerUrl: string): Promise<{
    codeVerifier: string;
    codeChallenge: string;
    state: string;
  }> => {
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

  protected getClientCredentials = async (resourceServerUrl: string, authorizationServer: oauth.AuthorizationServer): Promise<ClientCredentials> => {
    let credentials = await this.db.getClientCredentials(resourceServerUrl);
    // If no credentials found, register a new client
    if (!credentials) {
      console.log(`No client credentials found for ${resourceServerUrl}, attempting dynamic client registration`);
      credentials = await this.registerClient(authorizationServer, resourceServerUrl);
    }
    return credentials;
  }

  protected getAuthorizeUrl = async (
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

  protected throwAuthorizationError = async (resourceServerUrl: string): Promise<void> => {
    console.log(`Throwing OAuthAuthenticationRequiredError for ${resourceServerUrl}`);
    
    // Get the authorization server configuration
    const authServerUrl = await this.getAuthorizationServerUrl(resourceServerUrl);
    const authorizationServer = await this.getAuthorizationServer(authServerUrl);
    
    // Get the client credentials
    let credentials = await this.getClientCredentials(resourceServerUrl, authorizationServer);
    
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

  protected makeOAuthClientAndAuth = async (
    credentials: ClientCredentials
  ): Promise<[oauth.Client, oauth.ClientAuth]> => {
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

    return [client, clientAuth];
  }

  protected makeTokenRequestAndClient = async (
    authorizationServer: oauth.AuthorizationServer,
    credentials: ClientCredentials,
    codeVerifier: string,
    authResponse: URLSearchParams
  ): Promise<[Response, oauth.Client]> => {
    const [client, clientAuth] = await this.makeOAuthClientAndAuth(credentials);

    const response = await oauth.authorizationCodeGrantRequest(
      authorizationServer,
      client,
      clientAuth,
      authResponse,
      credentials.redirectUri,
      codeVerifier, {
        [oauth.customFetch]: this.fetchFn,
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      }
    );
    return [response, client];
  }

  protected exchangeCodeForToken = async (
    authResponse: URLSearchParams,
    state: string,
    pkceValues: PKCEValues,
    authorizationServer: oauth.AuthorizationServer
  ): Promise<string> => {
    console.log(`Exchanging code for tokens with state: ${state}`);
    
    const { codeVerifier, resourceServerUrl } = pkceValues;
    
    // Get the client credentials
    let credentials = await this.getClientCredentials(resourceServerUrl, authorizationServer);
    
    let [response, client] = await this.makeTokenRequestAndClient(authorizationServer, credentials, codeVerifier, authResponse);

    if(response.status === 403 || response.status === 401) {
      console.log(`Bad response status exchanging code for token: ${response.statusText}. Could be due to bad client credentials - trying to re-register`);
      credentials = await this.registerClient(authorizationServer, resourceServerUrl);
      [response, client] = await this.makeTokenRequestAndClient(authorizationServer, credentials, codeVerifier, authResponse);
    }
    
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
        ? Date.now() + result.expires_in * 1000
        : undefined
    });
    
    return result.access_token;
  }

  protected getAccessToken = async (url: string): Promise<AccessToken | null> => {
    // Get the access token from the database
    let resourceServerUrl = OAuthClient.getResourceServerUrl(url);
    let parentPath = OAuthClient.getParentPath(resourceServerUrl);
    let tokenData = await this.db.getAccessToken(resourceServerUrl);
    // If there's no token for the requested path, see if there's one for the parent
    while (!tokenData && parentPath){
      console.log(`No access token found for ${resourceServerUrl}, trying parent ${parentPath}`);
      tokenData = await this.db.getAccessToken(parentPath);
      parentPath = OAuthClient.getParentPath(parentPath);
    }
    return tokenData;
  }

  protected tryRefreshToken = async (resourceServerUrl: string): Promise<AccessToken | null> => {
    let token = await this.getAccessToken(resourceServerUrl);
    if (!token) {
      console.log('No token found, cannot refresh');
      return null;
    }
    if (!token.refreshToken) {
      console.log('No refresh token found, cannot refresh');
      return null;
    }
    const authServerUrl = await this.getAuthorizationServerUrl(resourceServerUrl);
    const authorizationServer = await this.getAuthorizationServer(authServerUrl);
    const credentials = await this.getClientCredentials(resourceServerUrl, authorizationServer);
    const [client, clientAuth] = await this.makeOAuthClientAndAuth(credentials);

    const response = await oauth.refreshTokenGrantRequest(
      authorizationServer,
      client,
      clientAuth,
      token.refreshToken,
      {
        [oauth.customFetch]: this.fetchFn,
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      }
    );

    const result = await oauth.processRefreshTokenResponse(authorizationServer, client, response)
    const at = {
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      expiresAt: result.expires_in 
        ? Date.now() + result.expires_in * 1000
        : undefined
    };
    await this.db.saveAccessToken(resourceServerUrl, at);
    return at;
  }

  protected _doFetch = async (url: string, init?: RequestInit): Promise<Response> => {
    console.log(`Making ${init?.method || 'GET'} request to ${url}`);
    
    const tokenData = await this.getAccessToken(url);
    
    if (!tokenData) {
      console.log(`No access token found for resource server ${url}. Passing no authorization header.`);
    }

    const headers = (init?.headers || {}) as Record<string, string>;
    if (tokenData) {
      headers['Authorization'] = `Bearer ${tokenData.accessToken}`;
    }
    
    // Make the request with the access token
    const response = await this.fetchFn(url, {
      method: init?.method || 'GET',
      headers,
      body: init?.body
    });
    return response;
  }
}