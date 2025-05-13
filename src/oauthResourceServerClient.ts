import * as oauth from 'oauth4webapi';
import { FetchLike, OAuthClientDb, TokenData } from './types';
import { OAuthClient } from './oauthClient';

export class OAuthResourceServerClient extends OAuthClient {
  private authServerUrl: URL;

  // It's not actually expected that we'll every use the redirect_uri for this client - 
  // it's just going to be used to call the introspection endpoint with the
  // client credentials - but the OAuth spec requires us to provide a redirect_uri
  private static dummyRedirectUrl = 'https://127.0.0.1';

  constructor(authServerUrl: URL, db: OAuthClientDb, fetchFn: FetchLike = fetch, strict: boolean = true) {
    super(db, OAuthResourceServerClient.dummyRedirectUrl, false, fetchFn, strict);
    this.authServerUrl = authServerUrl;
  }

  override getRegistrationMetadata = async (resourceServerUrl: string): Promise<Partial<oauth.OmitSymbolProperties<oauth.Client>>> => {
    // Create client metadata for registration
    const clientMetadata = {
      redirect_uris: [OAuthResourceServerClient.dummyRedirectUrl],
      // We shouldn't actually need any response_types for this client either, but
      // the OAuth spec requires us to provide a response_type
      response_types: ['code'],
      grant_types: ['authorization_code', 'client_credentials'], 
      token_endpoint_auth_method: 'client_secret_basic',
      client_name: `Token Introspection Client for ${resourceServerUrl}`,
    }; 
    return clientMetadata;
  }

  introspectToken = async (token: string, additionalParameters?: Record<string, string>): Promise<TokenData> => {
    const authorizationServer = await this.getAuthorizationServer(this.authServerUrl);
    // When introspecting a token, the "resource" server that we want credentials for is the auth server
    const clientCredentials = await this.getClientCredentials(this.authServerUrl.toString(), authorizationServer);

    // Create a client for token introspection
    const client: oauth.Client = {
      client_id: clientCredentials.clientId,
      token_endpoint_auth_method: 'client_secret_basic'
    };
    
    // Create client authentication method
    const clientAuth = oauth.ClientSecretBasic(clientCredentials.clientSecret);
    
    // Use oauth4webapi's built-in token introspection
    const introspectionResponse = await oauth.introspectionRequest(
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