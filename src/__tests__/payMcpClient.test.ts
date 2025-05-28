import { SqliteOAuthDb } from '../oAuthDb';
import { OAuthAuthenticationRequiredError } from '../oAuth';
import { describe, it, expect, vi } from 'vitest';
import fetchMock from 'fetch-mock';
import { mockResourceServer, mockAuthorizationServer } from './testHelpers';
import { PayMcpClient } from '../payMcpClient';
import { OAuthDb, FetchLike, PaymentMaker } from '../types';

function payMcpClient(fetchFn: FetchLike, solanaPaymentMaker?: PaymentMaker, db?: OAuthDb, isPublic: boolean = false, strict: boolean = true) {
  solanaPaymentMaker = solanaPaymentMaker ?? {
    makePayment: vi.fn().mockResolvedValue('testPaymentId'),
    signBySource: vi.fn().mockResolvedValue('testSignature')
  };
  return new PayMcpClient(
    "bdj",
    db ?? new SqliteOAuthDb(':memory:'),
    'http://localhost:3000',
    isPublic,
    {'solana': solanaPaymentMaker},
    fetchFn,
    strict
  );
}
describe('payMcpClient.fetch', () => {
  it('should bubble up OAuthAuthenticationRequiredError on OAuth-but-not-PayMcp challenge', async () => {
    const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
    mockResourceServer(f, 'https://example.com', '/mcp', 'https://paymcp.com');
    mockAuthorizationServer(f, 'https://paymcp.com');

    const client = payMcpClient(f.fetchHandler);
    await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(OAuthAuthenticationRequiredError);
  });

  it('should throw an error if amount isnt specified', async () => {
    const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
    mockResourceServer(f, 'https://example.com', '/mcp', 'https://paymcp.com?payMcp=1&network=solana&destination=testDestination&currency=USDC');
    mockAuthorizationServer(f, 'https://paymcp.com', '?payMcp=1&network=solana&destination=testDestination&currency=USDC');
    const paymentMaker = {
      makePayment: vi.fn().mockResolvedValue('testPaymentId'),
      signBySource: vi.fn().mockResolvedValue('testSignature')
    };
    const client = payMcpClient(f.fetchHandler, paymentMaker);

    await expect(client.fetch('https://example.com/mcp')).rejects.toThrow(/amount not provided/);
  });

  it('should make a payment and post it to the authorization server for PayMcp challenge', async () => {
    const f = fetchMock.createInstance()
      // 401, then succeed
      .getOnce('https://example.com/mcp', 401)
      .getOnce('https://example.com/mcp', {data: 'data'});
    mockResourceServer(f, 'https://example.com', '/mcp', 'https://paymcp.com?payMcp=1&network=solana&destination=testDestination&currency=USDC&amount=0.01');
    mockAuthorizationServer(f, 'https://paymcp.com', '?payMcp=1&network=solana&destination=testDestination&currency=USDC&amount=0.01')
      // Respond to /authorize call 
      .get('begin:https://paymcp.com/authorize', (req) => {
        return {
          status: 301,
          headers: {location: `paymcp://paymcp?code=testCode&state=${new URL(req.args[0] as any).searchParams.get('state')}`}
        };
      });
    const paymentMaker = {
      makePayment: vi.fn().mockResolvedValue('testPaymentId'),
      signBySource: vi.fn().mockResolvedValue('testSignature')
    };
    const client = payMcpClient(f.fetchHandler, paymentMaker);

    await client.fetch('https://example.com/mcp');
    // Ensure we make a payment and sign it
    expect(paymentMaker.makePayment).toHaveBeenCalled();
    expect(paymentMaker.signBySource).toHaveBeenCalled();

    // Ensure we call the authorization endpoint
    const authCall = f.callHistory.lastCall('begin:https://paymcp.com/authorize');
    expect(authCall).toBeDefined();

    // Ensure there was an auth header with the payment id and signature
    const authHeader = (authCall!.args[1] as any).headers['Authorization'];
    expect(authHeader).toBeDefined();
    expect(authHeader).toContain('Bearer ');
    const encodedPayment = authHeader.split(' ')[1];
    const decodedPayment = Buffer.from(encodedPayment, 'base64').toString('utf-8');
    expect(decodedPayment).toBe('testPaymentId:testSignature');
  });

  it('should throw if PayMcp authorization server response is not successful', async () => {
    const f = fetchMock.createInstance()
      // 401, then succeed
      .getOnce('https://example.com/mcp', 401)
      .getOnce('https://example.com/mcp', {data: 'data'});
    mockResourceServer(f, 'https://example.com', '/mcp', 'https://paymcp.com?payMcp=1&network=solana&destination=testDestination&currency=USDC&amount=0.01');
    mockAuthorizationServer(f, 'https://paymcp.com', '?payMcp=1&network=solana&destination=testDestination&currency=USDC&amount=0.01')
      // Respond to /authorize call 
      .get('begin:https://paymcp.com/authorize', 401, {});
    const client = payMcpClient(f.fetchHandler);

    await expect(client.fetch('https://example.com/mcp')).rejects.toThrow('Expected redirect response from authorization URL, got 401');
  });

  it('should throw if authorization server authorization endpoint returns an error', async () => {
    // We can't save this - the authorization URL was constructed using the client_id, so 
    // if the client registration is no longer valid, there's nothing we can do.
    const f = fetchMock.createInstance().getOnce('https://example.com/mcp', 401);
    mockResourceServer(f, 'https://example.com', '/mcp', 'https://paymcp.com?payMcp=1&network=solana&destination=testDestination&currency=USDC&amount=0.01');
    mockAuthorizationServer(f, 'https://paymcp.com', '?payMcp=1&network=solana&destination=testDestination&currency=USDC&amount=0.01')
      /// Respond to /authorize call 
      .get('begin:https://paymcp.com/authorize', (req) => {
        const state = new URL(req.args[0] as any).searchParams.get('state');
        return {
          status: 301,
          // This is how the AS responds to a bad request, as per RFC 6749
          // It just redirects back to the client without a code and with an error
          headers: {location: `paymcp://paymcp?state=${state}&error=invalid_request`}
        };
      });

    const client = payMcpClient(f.fetchHandler);
    await expect(client.fetch('https://example.com/mcp')).rejects.toThrow('authorization response from the server is an error');
  });
});
