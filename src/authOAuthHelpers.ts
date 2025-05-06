import { ClientCredentials, OAuthClientDb } from './oauthClientDb.js';
import * as oauth from 'oauth4webapi';
import { allowInsecureRequests } from 'oauth4webapi';

export async function getAuthorizationServer(authServerUrl: URL): Promise<oauth.AuthorizationServer> {
  // Get the authorization server metadata
  const response = await oauth.discoveryRequest(authServerUrl, {
    algorithm: 'oauth2',
    [allowInsecureRequests]: process.env.NODE_ENV === 'development'
  });
  return await oauth.processDiscoveryResponse(authServerUrl, response); 
}

export async function registerClient(
  authorizationServer: oauth.AuthorizationServer,
  authServerUrl: URL,
  db: OAuthClientDb
): Promise<ClientCredentials> {
  // Check if the server supports dynamic client registration
  if (!authorizationServer.registration_endpoint) {
    console.log('[auth] Authorization server does not support dynamic client registration');
    throw new Error('Authorization server does not support dynamic client registration');
  }
  
  // Create client metadata for registration
  // It's not actually expected that we'll every use the redirect_uri for this client - 
  // it's just going to be used to call the introspection endpoint with the
  // client credentials - but the OAuth spec requires us to provide a redirect_uri
  const redirectUri = 'https://127.0.0.1';
  const clientMetadata: Partial<oauth.Client> = {
    redirect_uris: [redirectUri],
    // We shouldn't actually need any response_types for this client either, but
    // the OAuth spec requires us to provide a response_type
    response_types: ['code'],
    grant_types: ['authorization_code', 'client_credentials'], 
    token_endpoint_auth_method: 'client_secret_basic',
    client_name: `Token Introspection Client for ${authServerUrl}`,
  };
  
  // Make the registration request
  const regResponse = await oauth.dynamicClientRegistrationRequest(
    authorizationServer,
    clientMetadata,
    {
      [allowInsecureRequests]: process.env.NODE_ENV === 'development'
    }
  );
  
  // Process the registration response
  const registeredClient = await oauth.processDynamicClientRegistrationResponse(regResponse);
  
  // Create client credentials from the registration response
  const clientCredentials: ClientCredentials = {
    clientId: registeredClient.client_id,
    clientSecret: registeredClient.client_secret!.toString(), 
    redirectUri: redirectUri
  };
  
  // Save the credentials in the database
  await db.saveClientCredentials(authServerUrl.toString(), clientCredentials);
  
  console.log(`[auth] Registered as client with ID: ${clientCredentials.clientId}`);
  
  return clientCredentials;
}

export async function introspectToken(
  authorizationServer: oauth.AuthorizationServer,
  clientCredentials: ClientCredentials,
  token: string,
  additionalParameters?: Record<string, string>
): Promise<oauth.IntrospectionResponse> {
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
      [allowInsecureRequests]: process.env.NODE_ENV === 'development'
    }
  );
  
  // Process the introspection response
  return await oauth.processIntrospectionResponse(
    authorizationServer,
    client,
    introspectionResponse
  );
}