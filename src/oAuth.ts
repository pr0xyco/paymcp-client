//import { fetch as expoFetch } from 'expo/fetch';
import * as oauth from 'oauth4webapi';

import * as Crypto from 'expo-crypto';

import { OAuthGlobalClient } from './oAuthGlobalClient.js';
import { AccessToken, ClientCredentials, FetchLike, OAuthDb, PKCEValues } from './types.js';

export class OAuthAuthenticationRequiredError extends Error {
  constructor(
    public readonly url: string,
    public readonly resourceServerUrl: string
  ) {
    super(`OAuth authentication required. Resource server url: ${resourceServerUrl}`);
    this.name = 'OAuthAuthenticationRequiredError';
  }
}

// TODO: fetchHack is required on React Native - I've commented it out, but it'll break
/*const fetchHack = async (url: string, init: RequestInit) => {
  const resp1 = await expoFetch(url, init as any);
  const resp2 = new Response();
  (resp2 as any).headers = resp1.headers;
  (resp2 as any).status = resp1.status;
  (resp2 as any).statusText = resp1.statusText;
  (resp2 as any).ok = resp1.ok;
  (resp2 as any).type = resp1.type;
  (resp2 as any).url = resp1.url;
  (resp2 as any).bodyUsed = false;
  (resp2 as any).json = async () => await resp1.json();
  return resp2;
}*/

const CHUNK_SIZE = 0x8000
function encodeBase64Url(input: Uint8Array | ArrayBuffer) {
  if (input instanceof ArrayBuffer) {
    input = new Uint8Array(input)
  }

  const arr = []
  for (let i = 0; i < input.byteLength; i += CHUNK_SIZE) {
    // @ts-expect-error
    arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)))
  }
  return btoa(arr.join('')).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

export interface OAuthClientConfig {
  userId: string;
  db: OAuthDb;
  callbackUrl: string;
  isPublic: boolean;
  fetchFn?: FetchLike;
  sideChannelFetch?: FetchLike;
  strict?: boolean;
}

export class OAuthClient extends OAuthGlobalClient {
  protected db: OAuthDb;
  protected userId: string;
  protected fetchFn: FetchLike;

  constructor({
    userId,
    db,
    callbackUrl,
    isPublic,
    fetchFn = fetch,
    sideChannelFetch = fetch,
    strict = true
  }: OAuthClientConfig) {
    super({
      globalDb: db,
      callbackUrl,
      isPublic,
      sideChannelFetch,
      strict
    });
    this.db = db;
    this.userId = userId;
    this.fetchFn = fetchFn;
  }

  protected extractResourceUrl = (response: Response): string | null => {
    if (response.status !== 401) {
      return null;
    }
    const header = response.headers.get('www-authenticate') || '';
    let wwwAuthenticate = header || '';
    const match = header.match(/^Bearer resource_metadata="([^"]+)"$/);
    if (match) {
      wwwAuthenticate = match[1];
    }
    return this.normalizeResourceServerUrl(wwwAuthenticate);
  }

  fetch: FetchLike = async (url, init) => {
    let response = await this._doFetch(url, init);
    
    if (response.status === 401) {
      console.log('Received 401 Unauthorized status');

      let resourceUrl = this.extractResourceUrl(response);
      const calledUrl = OAuthClient.trimToPath(url);
      // If the response indicates an expired token, try to refresh it
      if (response.headers.get('www-authenticate')?.includes('error="invalid_grant"')) {
        console.log(`Response includes invalid_grant error, attempting to refresh token for ${resourceUrl}`);
        let refreshUrl = resourceUrl;
        if (!refreshUrl) {
          console.log(`Refresh: No resource url found in response www-authenticate header, falling back to the called url ${calledUrl} (this could be incorrect if the called server is just proxying back an oauth failure)`);
          refreshUrl = calledUrl;
        }
        const newToken = await this.tryRefreshToken(refreshUrl);
        if(newToken) {
          response = await this._doFetch(url, init);
          resourceUrl = this.extractResourceUrl(response);
        }
      }

      if (response.status === 401) /* still */ {
        // If we couldn't get a valid resourceServerUrl from wwwAuthenticate, use the original URL
        if (!resourceUrl) {
          console.log(`No resource url found in response www-authenticate header, falling back to the called url ${calledUrl} (this could be incorrect if the called server is just proxying back an oauth failure)`);
          resourceUrl = calledUrl;
        }
        console.log(`Throwing OAuthAuthenticationRequiredError for ${calledUrl}, resource: ${resourceUrl}`);
        throw new OAuthAuthenticationRequiredError(calledUrl, resourceUrl);
      }
    }
  
    return response;
  }

  makeAuthorizationUrl = async (url: string, resourceUrl: string): Promise<URL> => {
    console.log('entering makeAuthorizationUrl');
    resourceUrl = this.normalizeResourceServerUrl(resourceUrl);
    const authorizationServer = await this.getAuthorizationServer(resourceUrl);
    console.log('authorizationServer', authorizationServer);
    const credentials = await this.getClientCredentials(authorizationServer);
    console.log('credentials', credentials);
    const pkceValues = await this.generatePKCE(url, resourceUrl);
    console.log('pkceValues', pkceValues);
    const authorizationUrl = new URL(authorizationServer.authorization_endpoint || '');
    authorizationUrl.searchParams.set('client_id', credentials.clientId);
    authorizationUrl.searchParams.set('redirect_uri', credentials.redirectUri);
    authorizationUrl.searchParams.set('response_type', 'code');
    authorizationUrl.searchParams.set('code_challenge', pkceValues.codeChallenge);
    authorizationUrl.searchParams.set('code_challenge_method', 'S256');
    authorizationUrl.searchParams.set('state', pkceValues.state);
    console.log('returning from makeAuthorizationUrl', authorizationUrl);
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
    const authorizationServer = await this.getAuthorizationServer(pkceValues.resourceUrl);

    // Get the client credentials
    const credentials = await this.getClientCredentials(authorizationServer);
    
    // Create the client configuration
    const client: oauth.Client = { 
      client_id: credentials.clientId,
      token_endpoint_auth_method: 'client_secret_post'
    };
    
    console.log('validating auth response',authorizationServer,
      client,
      callbackUrl,
      state);
    // Validate the authorization response
    const authResponse = await oauth.validateAuthResponse(
      authorizationServer,
      client,
      callbackUrl,
      state
    );
    console.log('authResponse', authResponse instanceof URLSearchParams, (globalThis as any).REACT_NATIVE_URL_POLYFILL, authResponse.get('code'));

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

  protected generatePKCE = async (url: string, resourceUrl: string): Promise<{
    codeVerifier: string;
    codeChallenge: string;
    state: string;
  }> => {
    console.log('entering generatePKCE');
    resourceUrl = this.normalizeResourceServerUrl(resourceUrl);
    console.log('resourceUrl', resourceUrl);

    // Generate a random code verifier
    const codeVerifier = oauth.generateRandomCodeVerifier();
    console.log('codeVerifier', codeVerifier);
    // Calculate the code challenge
    // Don't use the oauth module to do this because it relies on crypto functions that
    // aren't available in React Native / Expo
    let codeChallenge: string | undefined;
    try {
      codeChallenge = encodeBase64Url(await Crypto.digest(
        Crypto.CryptoDigestAlgorithm.SHA256,
        new TextEncoder().encode(codeVerifier)
      ));
    } catch (e: any) {
      console.log("E", e, e.stack);
    }
    console.log('codeChallenge', codeChallenge);
    // Generate a random state
    const state = oauth.generateRandomState();
    console.log('state', state);

    // Save the PKCE values in the database
    await this.db.savePKCEValues(this.userId, state, {
      url,
      codeVerifier,
      codeChallenge: codeChallenge!,
      resourceUrl
    });
    
    console.log(`Generated PKCE values with state: ${state}`);
    return { codeVerifier, codeChallenge: codeChallenge!, state };
  }

  protected makeTokenRequestAndClient = async (
    authorizationServer: oauth.AuthorizationServer,
    credentials: ClientCredentials,
    codeVerifier: string,
    authResponse: URLSearchParams
  ): Promise<[Response, oauth.Client]> => {
    const [client, clientAuth] = this.makeOAuthClientAndAuth(credentials);

    const options: oauth.TokenEndpointRequestOptions = {
      //[oauth.customFetch]: fetchHack,
      [oauth.customFetch]: this.sideChannelFetch,
      [oauth.allowInsecureRequests]: this.allowInsecureRequests
    };
    /*const parameters = new URLSearchParams(options.additionalParameters)
    parameters.set('redirect_uri', credentials.redirectUri)
    parameters.set('code', authResponse.get('code') || '')
    parameters.set('code_verifier', codeVerifier)
    console.log(
      authResponse instanceof URLSearchParams,
      authResponse.get('code'),
      parameters.toString()
    );*/
    let response: Response | undefined;
    try {
      response = await oauth.authorizationCodeGrantRequest(
        authorizationServer,
        client,
        clientAuth,
        authResponse,
        credentials.redirectUri,
        codeVerifier, 
        options
      );
      console.log("response", response);
    } catch (e: any) {
      console.log("E", e, e.cause, e.error, e.error_description, e.stack);
    }
    return [response!, client];
  }

  protected exchangeCodeForToken = async (
    authResponse: URLSearchParams,
    pkceValues: PKCEValues,
    authorizationServer: oauth.AuthorizationServer
  ): Promise<string> => {
    console.log(`Exchanging code for tokens`);
    
    const { codeVerifier, url, resourceUrl } = pkceValues;
    
    // Get the client credentials
    let credentials = await this.getClientCredentials(authorizationServer);
    console.log('credentials', credentials);
    let [response, client] = await this.makeTokenRequestAndClient(authorizationServer, credentials, codeVerifier, authResponse);
    console.log('response', response);
    console.log('client', client);
    if(response.status === 403 || response.status === 401) {
      console.log(`Bad response status exchanging code for token: ${response.statusText}. Could be due to bad client credentials - trying to re-register`);
      credentials = await this.registerClient(authorizationServer);
      [response, client] = await this.makeTokenRequestAndClient(authorizationServer, credentials, codeVerifier, authResponse);
    }
    console.log("A")

    let result: oauth.TokenEndpointResponse | undefined;
    try {
      // Process the token response
      result = await oauth.processAuthorizationCodeResponse(
        authorizationServer,
        client,
        response
      );
      console.log("result", result);
    } catch (e: any) {
      console.log("E", e, e.cause, e.error, e.error_description, e.stack);
    }
    
    console.log("B", this.userId, url);
    // Save the access token in the database
    await this.db.saveAccessToken(this.userId, url, {
      resourceUrl,
      accessToken: result!.access_token,
      refreshToken: result!.refresh_token,
      expiresAt: result!.expires_in 
        ? Date.now() + result!.expires_in * 1000
        : undefined
    });
    console.log("C")
    
    return result!.access_token;
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
    const authorizationServer = await this.getAuthorizationServer(token.resourceUrl);
    const credentials = await this.getClientCredentials(authorizationServer);
    const [client, clientAuth] = this.makeOAuthClientAndAuth(credentials);

    const response = await oauth.refreshTokenGrantRequest(
      authorizationServer,
      client,
      clientAuth,
      token.refreshToken,
      {
        [oauth.customFetch]: this.sideChannelFetch,
        [oauth.allowInsecureRequests]: this.allowInsecureRequests
      }
    );

    const result = await oauth.processRefreshTokenResponse(authorizationServer, client, response)
    const at = {
      resourceUrl: token.resourceUrl,
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
    console.log('tokenData', tokenData);
    if (!tokenData) {
      console.log(`No access token found for resource server ${url}. Passing no authorization header.`);
    }

    if (tokenData) {
      init = init || {};
      const headers = new Headers(init.headers);
      headers.set('Authorization', `Bearer ${tokenData.accessToken}`);
      init.headers = headers;
    }
    console.log('init', init);
    // Make the request with the access token
    try {
      const response = await this.fetchFn(url, init);
      console.log('response', response);
      return response;
    } catch (e: any) {
      console.log("E", e, e.stack);
      throw e;
    }
  }
}