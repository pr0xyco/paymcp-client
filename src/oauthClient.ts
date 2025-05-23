import * as oauth from 'oauth4webapi';
import { URL } from 'url';
import { FetchLike, ClientCredentials, PKCEValues, AccessToken, OAuthDb} from './types';
import { OAuthGlobalClient } from './oAuthGlobalClient';

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

export class OAuthClient extends OAuthGlobalClient {
  protected db: OAuthDb;
  protected userId: string;

  constructor(userId: string, db: OAuthDb, callbackUrl: string, isPublic: boolean, fetchFn: FetchLike = fetch, strict: boolean = true) {
    super(db, callbackUrl, isPublic, fetchFn, strict);
    this.db = db;
    this.userId = userId;
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
    const pkceValues = await this.db.getPKCEValues(this.userId, state);
    if (!pkceValues) {
      throw new Error(`No PKCE values found for state: ${state}`);
    }
    
    // Get the authorization server configuration
    const authServerUrl = await this.getAuthorizationServerUrl(pkceValues.resourceServerUrl);
    const authorizationServer = await this.getAuthorizationServer(authServerUrl);

    // Get the client credentials
    const credentials = await this.getClientCredentials(authorizationServer);
    
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

  override getRegistrationMetadata = async (): Promise<Partial<oauth.OmitSymbolProperties<oauth.Client>>> => {
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
      client_name: `OAuth Client for ${this.callbackUrl}`,
    };
    return clientMetadata;
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
    await this.db.savePKCEValues(this.userId, state, {
      codeVerifier,
      codeChallenge,
      resourceServerUrl
    });
    
    console.log(`Generated PKCE values with state: ${state}`);
    return { codeVerifier, codeChallenge, state };
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
    let credentials = await this.getClientCredentials(authorizationServer);
    
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
    let credentials = await this.getClientCredentials(authorizationServer);
    
    let [response, client] = await this.makeTokenRequestAndClient(authorizationServer, credentials, codeVerifier, authResponse);

    if(response.status === 403 || response.status === 401) {
      console.log(`Bad response status exchanging code for token: ${response.statusText}. Could be due to bad client credentials - trying to re-register`);
      credentials = await this.registerClient(authorizationServer);
      [response, client] = await this.makeTokenRequestAndClient(authorizationServer, credentials, codeVerifier, authResponse);
    }
    
    // Process the token response
    const result = await oauth.processAuthorizationCodeResponse(
      authorizationServer,
      client,
      response
    );
    
    // Save the access token in the database
    await this.db.saveAccessToken(this.userId, resourceServerUrl, {
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
    let tokenData = await this.db.getAccessToken(this.userId, resourceServerUrl);
    // If there's no token for the requested path, see if there's one for the parent
    while (!tokenData && parentPath){
      console.log(`No access token found for ${resourceServerUrl}, trying parent ${parentPath}`);
      tokenData = await this.db.getAccessToken(this.userId, parentPath);
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
    const credentials = await this.getClientCredentials(authorizationServer);
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
    await this.db.saveAccessToken(this.userId, resourceServerUrl, at);
    return at;
  }

  protected _doFetch = async (url: string, init?: RequestInit): Promise<Response> => {
    console.log(`Making ${init?.method || 'GET'} request to ${url}`);
    
    const tokenData = await this.getAccessToken(url);
    
    if (!tokenData) {
      console.log(`No access token found for resource server ${url}. Passing no authorization header.`);
    }

    if (tokenData) {
      init = init || {};
      const headers = new Headers(init.headers);
      headers.set('Authorization', `Bearer ${tokenData.accessToken}`);
      init.headers = headers;
    }
    
    // Make the request with the access token
    const response = await this.fetchFn(url, init);
    return response;
  }
}