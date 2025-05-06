import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { localhostOnly, requireBearerAuth, requireOAuthUser } from '../src/auth.js';
import * as authOAuthHelpers from '../src/authOAuthHelpers.js';
import crypto from 'crypto';
import httpMocks from 'node-mocks-http';
import { SqliteOAuthClientDb } from '../src/oauthClientDb.js';
import * as oauth from 'oauth4webapi';

// Generate a proper encryption key for tests
const TEST_ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');

describe('getOAuthAuthUser', () => {
  let db: SqliteOAuthClientDb;
  const validToken = 'valid-test-token';
  const userId = 'test-user';
  const auth_server_url = 'http://127.0.0.1:3000';

  beforeEach(async () => {
    // Create a real Sqlite model with in-memory database
    db = new SqliteOAuthClientDb(':memory:', TEST_ENCRYPTION_KEY);
    
    // Mock the authorization server functions
    vi.spyOn(authOAuthHelpers, 'registerClient').mockImplementation(async () => {
      return {
        clientId: 'test-client',
        clientSecret: 'test-secret',
        redirectUri: 'http://127.0.0.1:3000/callback'
      };
    });
    vi.spyOn(authOAuthHelpers, 'introspectToken').mockImplementation(async (a, b, token: string) => {
      return {
        active: token == validToken,
        sub: userId
      };
    });
    vi.spyOn(authOAuthHelpers, 'getAuthorizationServer').mockResolvedValue({
      authorization_endpoint: auth_server_url,
    } as oauth.AuthorizationServer);
  });

  afterEach(async () => {
    await db.close();
  });

  it('should return undefined when no authorization header is present', async () => {
    const req = httpMocks.createRequest();
    const res = httpMocks.createResponse();

    const fn = requireOAuthUser(auth_server_url, db);
    const user = await fn(req, res);
    expect(user).toBeUndefined();
    expect(res.statusCode).toEqual(401);
    expect(res._getData().toString()).toContain("No token provided");
  });

  it('should return a Protected Resource Metadata URL in the WWW-Authenticate header', async () => {
    const req = httpMocks.createRequest({
      host: 'example.com',
      protocol: 'https'
    });
    const res = httpMocks.createResponse();

    const fn = requireOAuthUser(auth_server_url, db);
    const user = await fn(req, res);
    expect(user).toBeUndefined();
    expect(res.statusCode).toEqual(401);
    expect(res._getData().toString()).toContain("No token provided");
    expect(res._getHeaders()['www-authenticate']).toEqual('https://example.com/.well-known/oauth-protected-resource');
  });

  it('should set Protected Resource Metadata URL to path matching the request path', async () => {
    const req = httpMocks.createRequest({ 
      path: '/mypath',
      host: 'example.com',
      protocol: 'https'
    });
    const res = httpMocks.createResponse();

    const fn = requireOAuthUser(auth_server_url, db);
    const user = await fn(req, res);
    expect(user).toBeUndefined();
    expect(res.statusCode).toEqual(401);
    expect(res._getData().toString()).toContain("No token provided");
    expect(res._getHeaders()['www-authenticate']).toEqual('https://example.com/.well-known/oauth-protected-resource/mypath');
  });

  it('should return undefined when authorization header does not start with Bearer', async () => {
    const req = httpMocks.createRequest({ headers: { authorization: 'Basic token123' } });
    const res = httpMocks.createResponse();

    const fn = requireOAuthUser(auth_server_url, db);
    const user = await fn(req, res);
    expect(user).toBeUndefined();
    expect(res.statusCode).toEqual(401);
    expect(res._getData().toString()).toContain("No token provided");
  });

  it('should return undefined when token is invalid', async () => {
    const req = httpMocks.createRequest({ headers: { authorization: 'Bearer invalid-token' } });
    const res = httpMocks.createResponse();

    const fn = requireOAuthUser(auth_server_url, db);
    const user = await fn(req, res);
    expect(user).toBeUndefined();
    expect(res.statusCode).toEqual(401);
  });

  it('should return user ID when token is valid', async () => {
    const req = httpMocks.createRequest({ headers: { authorization: `Bearer ${validToken}` } });
    const res = httpMocks.createResponse();

    const fn = requireOAuthUser(auth_server_url, db);
    const user = await fn(req, res);
    expect(user).toBe(userId);
    expect(res.statusCode).toEqual(200);
  });
}); 