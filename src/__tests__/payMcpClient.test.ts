import { OAuthClientDb, SqliteOAuthClientDb } from '../oauthClientDb';
import { OAuthClient, OAuthAuthenticationRequiredError } from '../oauthClient';
import { describe, it, expect } from 'vitest';
import fetchMock from 'fetch-mock';
import { mockResourceServer, mockAuthorizationServer } from './testHelpers';
import { PayMcpClient } from '../payMcpClient';
import { FetchLike } from '../types';

function payMcpClient(fetchFn: FetchLike, db?: OAuthClientDb, isPublic: boolean = false, strict: boolean = true) {
  return new PayMcpClient(
    db ?? new SqliteOAuthClientDb(':memory:'),
    isPublic,
    {},
    fetchFn,
    strict
  );
}
describe('payMcpClient.fetch', () => {
  it('should return response if request returns 200', async()=> {
    expect.fail();
  });

  it('should return request on non-OAuth-challenge 401', async () => {
    expect.fail();
  });

  it('should bubble up OAuthAuthenticationRequiredError on OAuth-but-not-PayMcp challenge', async () => {
    expect.fail();
  });

  it('should make a payment and post it to the authorization server for PayMcp challenge', async () => {
    expect.fail();
  });

  it('should do OAuth handleCallback if PayMcp authorization server response is successful', async () => {
    expect.fail();
  });

  it('should throw if PayMcp authorization server response is not successful', async () => {
    expect.fail();
  });

  it('should re-attempt the request if PayMcp authorization server response is successful', async () => {
    expect.fail();
  });

  it('should re-register client if authorization server authorization endpoint complains about an invalid client_id', async () => {
    const db = new SqliteOAuthClientDb(':memory:');
    db.saveClientCredentials('https://example.com/mcp', {
      clientId: 'old-client-id',
      clientSecret: 'old-client-secret',
      redirectUri: 'paymcp://paymcp'
    });
    const f = fetchMock.mockGlobal().getOnce('https://example.com/mcp', 401);
    mockResourceServer(f, 'https://example.com', '/mcp');
    mockAuthorizationServer(f, 'https://paymcp.com')
      // Simulate bad credentials response from the the AS response
      .get('https://paymcp.com/authorize', 400);

    const client = payMcpClient(f.fetchHandler, db);
    try {
      await client.fetch('https://example.com/mcp');
    }
    catch (e: any) {
      const err = e as OAuthAuthenticationRequiredError;
      expect(err.message).toContain('OAuth authentication required');
      const authUrl = err.authorizationUrl.toString();
    }
    await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
    const registerCall = f.callHistory.lastCall('https://paymcp.com/register');
    expect(registerCall).toBeDefined();
    const clientCredentials = await db.getClientCredentials('https://example.com/mcp');
    expect(clientCredentials?.clientId).not.toBe('old-client-id');
    expect(clientCredentials?.clientSecret).not.toBe('old-client-secret');
    expect.fail();
  });



  it('should re-register client if authorization server complains about an invalid redirect_uri', async () => {
    expect.fail();
  });
});
