import { describe, it, expect, vi, beforeEach, afterEach} from 'vitest';

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
});