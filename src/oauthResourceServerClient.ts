import * as oauth from 'oauth4webapi';
import { FetchLike, OAuthClientDb, TokenData } from './types';
import { OAuthClient } from './oauthClient';

export class OAuthResourceServerClient extends OAuthClient {
  private authServerUrl: string;

  constructor(authServerUrl: string, db: OAuthClientDb, callbackUrl: string, fetchFn: FetchLike = fetch, strict: boolean = true) {
    super(db, callbackUrl, false, fetchFn, strict);
    this.authServerUrl = authServerUrl;
  }

  override getRegistrationMetadata = async (): Promise<Partial<oauth.OmitSymbolProperties<oauth.Client>>> => {
    // Create client metadata for registration
    const clientMetadata = {
      redirect_uris: [this.callbackUrl],
      // We shouldn't actually need any response_types for this client either, but
      // the OAuth spec requires us to provide a response_type
      response_types: ['code'],
      grant_types: ['authorization_code', 'client_credentials'], 
      token_endpoint_auth_method: 'client_secret_basic',
      client_name: `Token Introspection Client for ${this.callbackUrl}`,
    }; 
    return clientMetadata;
  }

  introspectToken = async (token: string, additionalParameters?: Record<string, string>): Promise<TokenData> => {
    const authorizationServer = await this.getAuthorizationServer(new URL(this.authServerUrl));
    // When introspecting a token, the "resource" server that we want credentials for is the auth server
    let clientCredentials = await this.getClientCredentials(authorizationServer);

    // Create a client for token introspection
    let client: oauth.Client = {
      client_id: clientCredentials.clientId,
      token_endpoint_auth_method: 'client_secret_basic'
    };
    
    // Create client authentication method
    let clientAuth = oauth.ClientSecretBasic(clientCredentials.clientSecret);
    
    // Use oauth4webapi's built-in token introspection
    let introspectionResponse = await oauth.introspectionRequest(
      authorizationServer,
      client,
      clientAuth,
      token,
      {
        additionalParameters,
        [oauth.customFetch]: this.fetchFn,
        [oauth.allowInsecureRequests]: process.env.NODE_ENV === 'development'
      }
    );

    if(introspectionResponse.status === 403 || introspectionResponse.status === 401) {
      console.log(`Bad response status doing token introspection: ${introspectionResponse.statusText}. Could be due to bad client credentials - trying to re-register`);
      clientCredentials = await this.registerClient(authorizationServer);
      client = {
        client_id: clientCredentials.clientId,
        token_endpoint_auth_method: 'client_secret_basic'
      };
      clientAuth = oauth.ClientSecretBasic(clientCredentials.clientSecret);
      introspectionResponse = await oauth.introspectionRequest(
        authorizationServer,
        client,
        clientAuth,
        token,
        { 
          additionalParameters, 
          [oauth.customFetch]: this.fetchFn, 
          [oauth.allowInsecureRequests]: process.env.NODE_ENV === 'development'
        }
      );
    }
    
    // Process the introspection response
    const tokenData = await oauth.processIntrospectionResponse(
      authorizationServer,
      client,
      introspectionResponse
    );

    return {
      active: tokenData.active,
      scope: tokenData.scope,
      sub: tokenData.sub,
      aud: tokenData.aud
    };
  }
}