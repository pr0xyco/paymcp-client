import { describe, it, expect, vi, beforeEach, afterEach} from 'vitest';

describe('oauthClient.getAuthorizationServer', () => {
  it('should make resource server PRM request', async () => {
    expect.fail();
  });

  it('should strip querystring for PRM request URL', async () => {
    expect.fail();
  });

  it('should try to request AS metadata from resource server if PRM doc cannot be found', async () => {
    expect.fail();
  });

  it('should attempt to use fallback urls on the resource server if no PRM doc or Oauth metadata from resource server', async () => {
    expect.fail();
  });

  it('should throw if there is no way to find AS endpoints from resource server', async () => {
    expect.fail();
  });

  it('should make Authorization Server metadata request', async () => {
    expect.fail();
  });

  it('should attempt to use fallback urls on the AS if no AS metadata can be found', async () => {
    expect.fail();
  });

  it('should throw if there is no way to find AS endpoints from authorization server', async () => {
    expect.fail();
  });
});

describe('oauthClient.fetch', () => {
  it('should return response if request returns 200', async()=> {
    expect.fail();
  });

  it('should return request on non-OAuth-challenge 401', async () => {
    expect.fail();
  });

  it('should throw OAuthAuthenticationRequiredError with authorization url on OAuth challenge', async () => {
    expect.fail();
  });

  it('should send token in request to resource server if one exists in the DB', async () => {
    expect.fail();
  });

  it('should send a stored token for the parent path if no token exists for the resource path', async () => {
    expect.fail();
  });

  it('should not send a header if no token exists', async () => {
    expect.fail();
  });

  it('should construct authorization url with stored credentials if they exist', async () => {
    expect.fail();
  });

  it('should register client if there are no stored credentials', async () => {
    expect.fail();
  });

  it('should re-register client if authorization server complains about an invalid client_id', async () => {
    expect.fail();
  });

  it('should re-register client if authorization server complains about an invalid redirect_uri', async () => {
    expect.fail();
  });

  it('should make client registration request', async () => {
    expect.fail();
  });

  it('should throw if client registration request fails', async () => {
    expect.fail();
  });
}); 

describe('oauthClient.registerClient', () => {
  it('should configure safe metadata for public clients', async () => {
    expect.fail();
  });

  it('should configure metadata for private clients', async () => {
    expect.fail();
  });
});

describe('oauthClient.handleCallback', () => {
  it('should exchange code for token', async () => {
    expect.fail();
  });

  it('should save tokens to the DB', async () => {
    expect.fail();
  });

  it('should throw if no PKCE values found for state', async () => {
    // There's no saving this - if we don't have PKCE values anymore, we can't exchange code for token
    expect.fail();
  });

  it('should re-register client if no client credentials are found', async () => {
    expect.fail();
  });

  it('should re-register client if code exchange fails with bad credentials', async () => {
    expect.fail();
  });
});
