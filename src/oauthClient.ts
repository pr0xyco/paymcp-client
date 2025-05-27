import * as oauth from 'oauth4webapi';
import { URL } from 'url';
import { FetchLike, ClientCredentials, PKCEValues, AccessToken, OAuthDb} from './types';
import { OAuthGlobalClient } from './oAuthGlobalClient.js';

export class OAuthAuthenticationRequiredError extends Error {
  constructor(
    public readonly url: string,
    public readonly resourceServerUrl: string
  ) {
    super(`OAuth authentication required: ${resourceServerUrl}`);
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

  protected resourceServerRequired = (response: Response): string | null => {
    if (response.status !== 401) {
      return null;
    }
    const wwwAuthenticate = response.headers.get('www-authenticate') || '';
    if (URL.canParse(wwwAuthenticate)) {
      return wwwAuthenticate;
    }
    return null;
  }

  fetch: FetchLike = async (url, init) => {
    let response = await this._doFetch(url, init);
    
    if (response.status === 401) {
      console.log('Received 401 Unauthorized status');

      let resourceServerUrl = this.resourceServerRequired(response);
      // If the response indicates an expired token, try to refresh it
      if (response.headers.get('www-authenticate')?.includes('error="invalid_grant"')) {
        // TODO: We're assuming here that the url we're fetching from IS the resource server
        // That's not always true
        const calledServer = OAuthClient.trimToPath(url);
        console.log(`Response includes invalid_grant error, attempting to refresh token from ${calledServer}`);
        const newToken = await this.tryRefreshToken(calledServer);
        if(newToken) {
          response = await this._doFetch(url, init);
          resourceServerUrl = this.resourceServerRequired(response);
        }
      }

      if (response.status === 401) /* still */ {
        // If we couldn't get a valid resourceServerUrl from wwwAuthenticate, use the original URL
        if (!resourceServerUrl) {
          console.log(`No resource server url found in response www-authenticate header, falling back to the called url (this could be incorrect if the called server is just proxying back an oauth failure)`);
          resourceServerUrl = OAuthClient.trimToPath(url);
        }
        console.log(`Throwing OAuthAuthenticationRequiredError for ${OAuthClient.trimToPath(url)} accessing ${resourceServerUrl}`);
        throw new OAuthAuthenticationRequiredError(OAuthClient.trimToPath(url), resourceServerUrl);
      }
    }
  
    return response;
  }

  makeAuthorizationUrl = async (url: string, resourceServerUrl: string): Promise<URL> => {
    const authorizationServer = await this.getAuthorizationServer(resourceServerUrl);
    const credentials = await this.getClientCredentials(authorizationServer);
    const pkceValues = await this.generatePKCE(url, resourceServerUrl);

    const authorizationUrl = new URL(authorizationServer.authorization_endpoint || '');
    authorizationUrl.searchParams.set('client_id', credentials.clientId);
    authorizationUrl.searchParams.set('redirect_uri', credentials.redirectUri);
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('code_challenge', pkceValues.codeChallenge);
    authorizationUrl.searchParams.set('code_challenge_method', 'S256');
    authorizationUrl.searchParams.set('state', pkceValues.state);
    return authorizationUrl;
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
    const authorizationServer = await this.getAuthorizationServer(pkceValues.resourceServerUrl);

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
    await this.exchangeCodeForToken(authResponse, pkceValues, authorizationServer);
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

  protected generatePKCE = async (url: string, resourceServerUrl: string): Promise<{
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
      url,
      codeVerifier,
      codeChallenge,
      resourceServerUrl
    });
    
    console.log(`Generated PKCE values with state: ${state}`);
    return { codeVerifier, codeChallenge, state };
  }

  protected makeTokenRequestAndClient = async (
    authorizationServer: oauth.AuthorizationServer,
    credentials: ClientCredentials,
    codeVerifier: string,
    authResponse: URLSearchParams
  ): Promise<[Response, oauth.Client]> => {
    const [client, clientAuth] = this.makeOAuthClientAndAuth(credentials);

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
    pkceValues: PKCEValues,
    authorizationServer: oauth.AuthorizationServer
  ): Promise<string> => {
    console.log(`Exchanging code for tokens`);
    
    const { codeVerifier, url, resourceServerUrl } = pkceValues;
    
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
    await this.db.saveAccessToken(this.userId, url, {
      resourceServerUrl,
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
    url = OAuthClient.trimToPath(url);
    let parentPath = OAuthClient.getParentPath(url);
    let tokenData = await this.db.getAccessToken(this.userId, url);
    // If there's no token for the requested path, see if there's one for the parent
    // TODO: re-evaluate if we should recurse up to parent paths to find tokens
    // IIRC this is mainly to support SSE transport's separate /mcp and /mcp/message paths
    while (!tokenData && parentPath){
      console.log(`No access token found for ${url}, trying parent ${parentPath}`);
      tokenData = await this.db.getAccessToken(this.userId, parentPath);
      parentPath = OAuthClient.getParentPath(parentPath);
    }
    return tokenData;
  }

  protected tryRefreshToken = async (url: string): Promise<AccessToken | null> => {
    url = OAuthClient.trimToPath(url);
    let token = await this.getAccessToken(url);
    if (!token) {
      console.log('No token found, cannot refresh');
      return null;
    }
    if (!token.refreshToken) {
      console.log('No refresh token found, cannot refresh');
      return null;
    }
    const authorizationServer = await this.getAuthorizationServer(token.resourceServerUrl);
    const credentials = await this.getClientCredentials(authorizationServer);
    const [client, clientAuth] = this.makeOAuthClientAndAuth(credentials);

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
      resourceServerUrl: token.resourceServerUrl,
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      expiresAt: result.expires_in 
        ? Date.now() + result.expires_in * 1000
        : undefined
    };
    await this.db.saveAccessToken(this.userId, url, at);
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