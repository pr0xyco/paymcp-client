import { SqliteOAuthClientDb } from '../oauthClientDb';
import { OAuthClient, OAuthAuthenticationRequiredError } from '../oauthClient';
import { describe, it, expect } from 'vitest';
import fetchMock from 'fetch-mock';
import { FetchLike, OAuthClientDb } from '../types';
import { mockResourceServer, mockAuthorizationServer } from './testHelpers';

function oauthClient(fetchFn: FetchLike, db?: OAuthClientDb, isPublic: boolean = false, strict: boolean = true, callbackUrl: string = 'https://example.com/callback') {
  return new OAuthClient(
    db ?? new SqliteOAuthClientDb(':memory:'),
    callbackUrl,
    isPublic,
    fetchFn,
    strict
  );
}

describe('oauthClient', () => {
  describe('.fetch', () => {
    it('should return response if request returns 200', async()=> {
      const f = fetchMock.createInstance().any(200);

      const client = oauthClient(f.fetchHandler);
      const res = await client.fetch('https://example.com');
      expect(res.status).toBe(200);
    });

    it('should return request on (non-OAuth-challenge) 400', async () => {
      const f = fetchMock.createInstance().any(400);

      const client = oauthClient(f.fetchHandler);
      const res = await client.fetch('https://example.com');
      expect(res.status).toBe(400);
    });

    it('should throw OAuthAuthenticationRequiredError with authorization url on OAuth challenge', async () => {
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
    });

    it('should send token in request to resource server if one exists in the DB', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      db.saveAccessToken('https://example.com/mcp', {
        accessToken: 'test-access-token',
        expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 30
      });
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, db)
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const mcpCall = f.callHistory.lastCall('https://example.com/mcp');
      expect((mcpCall?.options?.headers as any)?.['authorization']).toBe('Bearer test-access-token');
    });

    it('should NOT send a stored token for the parent path if no token exists for the resource path', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      // Note: not saving for /mcp
      //   We intentionally don't want to use a token for the parent to prevent sharing tokens in a multi-tenant
      // environment. It's possible we'll have to revisit this slightly if servers are creating different
      // resources for both the /sse and /message endpoints
      db.saveAccessToken('https://example.com', {
        accessToken: 'test-access-token',
        expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 30
      });
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, db);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const mcpCall = f.callHistory.lastCall('https://example.com/mcp');
      expect(mcpCall).toBeDefined();
      expect((mcpCall?.options?.headers as any)?.['authorization']).toBeUndefined();
    });

    it('should construct authorization url with stored credentials if they exist', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      db.saveClientCredentials('https://example.com/mcp', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'paymcp://paymcp'
      });
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, db);
      try {
        await client.fetch('https://example.com/mcp');
      }
      catch (e: any) {
        const err = e as OAuthAuthenticationRequiredError;
        expect(err.message).toContain('OAuth authentication required');
        expect(err.authorizationUrl.searchParams.get('client_id')).toBe('test-client-id');
        expect(err.authorizationUrl.searchParams.get('redirect_uri')).toBe('paymcp://paymcp');
        expect(err.authorizationUrl.searchParams.get('response_type')).toBe('code');
        expect(err.authorizationUrl.searchParams.get('state')).not.toBeNull();
        expect(err.authorizationUrl.searchParams.get('code_challenge')).not.toBeNull();
      }
    });

    it('should include saved code and state in authorization url', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      db.saveClientCredentials('https://example.com/mcp', {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'paymcp://paymcp'
      });
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, db);
      try {
        await client.fetch('https://example.com/mcp');
      }
      catch (e: any) {
        const err = e as OAuthAuthenticationRequiredError;
        expect(err.message).toContain('OAuth authentication required');
        const state = err?.authorizationUrl.searchParams.get('state');
        const codeChallenge = err?.authorizationUrl.searchParams.get('code_challenge');
        const pkce = await db.getPKCEValues(state!);
        expect(pkce).not.toBeNull();
        expect(pkce?.codeChallenge).toEqual(codeChallenge);
      }
    });

    it('should register client if there are no stored credentials', async () => {
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const registerCall = f.callHistory.lastCall('https://paymcp.com/register');
      expect(registerCall).toBeDefined();
    });

    it('should throw if client registration request fails', async () => {
      const f = fetchMock.createInstance().get('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com')
        .modifyRoute('https://paymcp.com/register', {method: 'post', response: {status: 400, body: {}}});


      const client = oauthClient(f.fetchHandler);
      await expect(client.fetch('https://example.com/mcp')).rejects.not.toThrow(OAuthAuthenticationRequiredError);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow('unexpected HTTP status code');
    });

    it('should use refresh token to get a new access token if the current one expires', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      const oldToken = {
        accessToken: 'oldAccessToken',
        // Expires in the future, but the server can invalidate tokens whenever it wants
        // regardless. Set the time in the future so future changes to the client don't
        // pre-emptively refresh the token and break this test case
        expiresAt: Date.now() + 1000,
        refreshToken: 'oldRefreshToken'
      };
      db.saveAccessToken('https://example.com/mcp', oldToken);

      const f = fetchMock.createInstance()
        .getOnce('https://example.com/mcp', {
          status: 401,
          headers: {
            'www-authenticate': 'Bearer error="invalid_grant", error_description="The refresh token has expired"'
          }
        })
        .getOnce('https://example.com/mcp', 200);

      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com')
        .modifyRoute('https://paymcp.com/token', {
          method: 'post',
          response: {
            status: 200,
            body: {
              access_token: 'newAccessToken',
              refresh_token: 'newRefreshToken',
              token_type: 'Bearer',
              expires_in: 3600
            }
          }});

      const client = oauthClient(f.fetchHandler, db);
      const res = await client.fetch('https://example.com/mcp');
      expect(res.status).toBe(200);
      const tokenCall = f.callHistory.lastCall('https://paymcp.com/token');
      expect(tokenCall).toBeDefined();
      const body = (tokenCall?.args?.[1] as any).body as URLSearchParams;
      // The request to refresh should have used the old refresh token
      expect(body.get('refresh_token')).toEqual('oldRefreshToken');
     
      // Should be updated in the database as well
      const token = await db.getAccessToken('https://example.com/mcp');
      expect(token).not.toBeNull();
      expect(token?.accessToken).toEqual('newAccessToken');
      expect(token?.refreshToken).toEqual('newRefreshToken');
      expect(token?.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should throw if the token refresh fails', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      const oldToken = {
        accessToken: 'oldAccessToken',
        // Expires in the future, but the server can invalidate tokens whenever it wants
        // regardless. Set the time in the future so future changes to the client don't
        // pre-emptively refresh the token and break this test case
        expiresAt: Date.now() + 1000,
        refreshToken: 'oldRefreshToken'
      };
      db.saveAccessToken('https://example.com/mcp', oldToken);

      const f = fetchMock.createInstance()
        .getOnce('https://example.com/mcp', {
          status: 401,
          headers: {
            'www-authenticate': 'Bearer error="invalid_grant", error_description="The refresh token has expired"'
          }
        })
        .getOnce('https://example.com/mcp', 200);

      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com')
        .modifyRoute('https://paymcp.com/token', {
          method: 'post',
          response: { status: 400, body: {}}
        });

      const client = oauthClient(f.fetchHandler, db);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow('Token Endpoint response (unexpected HTTP status code)');
    });
  }); 

  describe('.getAuthorizationServer', () => {
    it('should make resource server PRM request', async () => {
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const prmCall = f.callHistory.lastCall('https://example.com/.well-known/oauth-protected-resource/mcp');
      expect(prmCall).toBeDefined();
    });

    it('should strip querystring for PRM request URL', async () => {
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const prmCall = f.callHistory.lastCall('https://example.com/.well-known/oauth-protected-resource/mcp');
      expect(prmCall).toBeDefined();
      expect(prmCall?.args[0]).toBe('https://example.com/.well-known/oauth-protected-resource/mcp');
    });

    it('should try to request AS metadata from resource server if PRM doc cannot be found (non-strict mode)', async () => {
      // This is in violation of the MCP spec (the PRM endpoint is supposed to exist), but some older
      // servers serve OAuth metadata from the MCP server instead of PRM data, so we fallback to support them
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp')
        // Note: fetch-mock also supplies .removeRoute, but .modifyRoute has the nice property of
        // throwing if the route isn't already mocked, so we know we haven't screwed up the test
        .modifyRoute('https://example.com/.well-known/oauth-protected-resource/mcp', {response: {status: 404}})
        // Emulate the resource server serving AS metadata
        .get('https://example.com/.well-known/oauth-authorization-server', {
          issuer: 'https://paymcp.com',
          authorization_endpoint: 'https://paymcp.com/authorize',
          registration_endpoint: 'https://paymcp.com/register'
        });
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, new SqliteOAuthClientDb(':memory:'), true, false); // strict = false
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const prmCall = f.callHistory.lastCall('https://example.com/.well-known/oauth-protected-resource/mcp');
      expect(prmCall).toBeDefined();
      expect(prmCall?.response?.status).toBe(404);
      // Yes, example.com - again, this test is checking an old pattern where the resource server is
      // acting as it's own authorization server
      const asCall = f.callHistory.lastCall('https://example.com/.well-known/oauth-authorization-server');
      expect(asCall).toBeDefined();
    });

    it('should throw if there is no way to find AS endpoints from resource server', async () => {
      const f = fetchMock.createInstance().get('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp')
        // Note: fetch-mock also supplies .removeRoute, but .modifyRoute has the nice property of
        // throwing if the route isn't already mocked, so we know we haven't screwed up the test
        .modifyRoute('https://example.com/.well-known/oauth-protected-resource/mcp', {response: {status: 404}})

      const client = oauthClient(f.fetchHandler);
      await expect(client.fetch('https://example.com/mcp')).rejects.not.toThrow(OAuthAuthenticationRequiredError);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow('unexpected HTTP status code');
    });
  });

  describe('.registerClient', () => {
    it('should configure safe metadata for public clients', async () => {
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, new SqliteOAuthClientDb(':memory:'), true);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const registerCall = f.callHistory.lastCall('https://paymcp.com/register');
      expect(registerCall).toBeDefined();
      const body = JSON.parse((registerCall?.args?.[1] as any).body);
      expect(body.response_types).toEqual(["code"]);
      expect(body.grant_types).toEqual(["authorization_code", "refresh_token"]);
      expect(body.token_endpoint_auth_method).toEqual("none");
      expect(body.client_name).toEqual("OAuth Client for https://example.com/mcp");
    });

    it('should configure metadata for private clients', async () => {
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const client = oauthClient(f.fetchHandler, new SqliteOAuthClientDb(':memory:'), false);
      await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
      const registerCall = f.callHistory.lastCall('https://paymcp.com/register');
      expect(registerCall).toBeDefined();
      const body = JSON.parse((registerCall?.args?.[1] as any).body);
      expect(body.response_types).toEqual(["code"]);
      expect(body.grant_types).toEqual(["authorization_code", "refresh_token", "client_credentials"]);
      expect(body.token_endpoint_auth_method).toEqual("client_secret_post");
      expect(body.client_name).toEqual("OAuth Client for https://example.com/mcp");
    });
  });

  describe('.handleCallback', () => {
    it('should exchange code for token', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      let oauthError: OAuthAuthenticationRequiredError | undefined;
      const client = oauthClient(f.fetchHandler, db);
      try {
        await client.fetch('https://example.com/mcp');
      }
      catch (e: any) {
        oauthError = e as OAuthAuthenticationRequiredError;
      }

      const state = oauthError?.authorizationUrl.searchParams.get('state')!;
      const pkce = await db.getPKCEValues(state);
      expect(pkce).not.toBeNull();

      const authCallbackUrl = `https://example.com/callback?code=test-code&state=${state}`;
      await client.handleCallback(authCallbackUrl);
      const tokenCall = f.callHistory.lastCall('https://paymcp.com/token');
      expect(tokenCall).toBeDefined();
      const body = (tokenCall?.args?.[1] as any).body as URLSearchParams;
      expect(body.get('code')).toEqual('test-code');
      expect(body.get('code_verifier')).toEqual(pkce?.codeVerifier);
      expect(body.get('grant_type')).toEqual('authorization_code');
    });

    it('should save tokens to the DB', async () => {
      const db = new SqliteOAuthClientDb(':memory:');
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      let oauthError: OAuthAuthenticationRequiredError | undefined;
      const client = oauthClient(f.fetchHandler, db);
      try {
        await client.fetch('https://example.com/mcp');
      }
      catch (e: any) {
        oauthError = e as OAuthAuthenticationRequiredError;
      }

      const state = oauthError?.authorizationUrl.searchParams.get('state')!;

      const authCallbackUrl = `https://example.com/callback?code=test-code&state=${state}`;
      await client.handleCallback(authCallbackUrl);

      const token = await db.getAccessToken('https://example.com/mcp');
      expect(token).not.toBeNull();
      expect(token?.accessToken).toEqual('testAccessToken');
      expect(token?.expiresAt).toBeGreaterThan(Date.now());
    });

    it('should throw if no PKCE values found for state', async () => {
      // There's no saving this - if we don't have PKCE values anymore, we can't exchange code for token
      const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      let oauthError: OAuthAuthenticationRequiredError | undefined;
      const client = oauthClient(f.fetchHandler);
      try {
        await client.fetch('https://example.com/mcp');
      }
      catch (e: any) {
        oauthError = e as OAuthAuthenticationRequiredError;
      }

      const authCallbackUrl = `https://example.com/callback?code=test-code&state=invalid-state`;
      await expect(client.handleCallback(authCallbackUrl)).rejects.toThrow('No PKCE values found for state');
    });

    it('should re-register client if no client credentials are found', async () => {
      const f = fetchMock.createInstance();
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com');

      const db = new SqliteOAuthClientDb(':memory:');
      db.savePKCEValues('test-state', {
        codeVerifier: 'test-code-verifier',
        codeChallenge: 'test-code-challenge',
        resourceServerUrl: 'https://example.com/mcp'
      });
      // Do NOT save client credentials, or do the OAuth flow to create them

      const client = oauthClient(f.fetchHandler, db);

      const authCallbackUrl = `https://example.com/callback?code=test-code&state=test-state`;
      await client.handleCallback(authCallbackUrl);
      const registerCall = f.callHistory.lastCall('https://paymcp.com/register');
      expect(registerCall).toBeDefined();
    });

    it('should re-register client if code exchange fails with bad credentials', async () => {
      const f = fetchMock.createInstance();
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com')
        .modifyRoute('https://paymcp.com/token', {method: 'post', response: {status: 401, body: {}}})
        .postOnce('https://paymcp.com/token', 
          {
            access_token: 'test-access-token',
            refresh_token: 'test-refresh-token',
            token_type: 'Bearer',
            expires_in: 3600
          });

      const db = new SqliteOAuthClientDb(':memory:');
      db.savePKCEValues('test-state', {
        codeVerifier: 'test-code-verifier',
        codeChallenge: 'test-code-challenge',
        resourceServerUrl: 'https://example.com/mcp'
      });
      // Save old credentials
      db.saveClientCredentials('https://example.com/mcp', {
        clientId: 'bad-client-id',
        clientSecret: 'bad-client-secret',
        redirectUri: 'paymcp://paymcp'
      });

      const client = oauthClient(f.fetchHandler, db);

      const authCallbackUrl = `https://example.com/callback?code=test-code&state=test-state`;
      await client.handleCallback(authCallbackUrl);
    });


    it('should throw if authorization server authorization endpoint returns an error', async () => {
      // We can't save this - the authorization URL was constructed using the client_id, so 
      // if the client registration is no longer valid, there's nothing we can do.
      const db = new SqliteOAuthClientDb(':memory:');
      db.savePKCEValues('test-state', {
        codeVerifier: 'test-code-verifier',
        codeChallenge: 'test-code-challenge',
        resourceServerUrl: 'https://example.com/mcp'
      });
      const f = fetchMock.mockGlobal();
      mockResourceServer(f, 'https://example.com', '/mcp');
      mockAuthorizationServer(f, 'https://paymcp.com')
  
      // This is how the AS responds to a bad request, as per RFC 6749
      // It just redirects back to the client without a code and with an error
      const authCallbackUrl = `https://example.com/callback?state=test-state&error=invalid_request`;
      const client = oauthClient(f.fetchHandler, db);
      await expect(client.handleCallback(authCallbackUrl)).rejects.toThrow('authorization response from the server is an error');
    });
  });
});
