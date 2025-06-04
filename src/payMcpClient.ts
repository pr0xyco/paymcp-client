import { BigNumber } from 'bignumber.js';
import { OAuthAuthenticationRequiredError, OAuthClient } from './oAuth';
import type { FetchLike, OAuthDb, PaymentMaker } from './types';

export interface PayMcpClientConfig {
  userId: string;
  db: OAuthDb;
  isPublic: boolean;
  paymentMakers: {[key: string]: PaymentMaker};
  fetchFn?: FetchLike;
  sideChannelFetch?: FetchLike;
  strict?: boolean;
}

export class PayMcpClient {
  protected oauthClient: OAuthClient;
  protected paymentMakers: Map<string, PaymentMaker>;
  protected sideChannelFetch: FetchLike;

  constructor({
    userId,
    db,
    paymentMakers,
    isPublic = false,
    fetchFn = fetch,
    sideChannelFetch = fetch,
    strict = true
  }: PayMcpClientConfig) {
    // PayMcpClient should never actually use the callback url - instead of redirecting the user to 
    // an authorization url which redirects back to the callback url, PayMcpClient posts the payment
    // directly to the authorization server, then does the token exchange itself
    this.oauthClient = new OAuthClient({
      userId,
      db,
      callbackUrl: 'http://localhost:3000/unused-dummy-paymcp-callback',
      isPublic,
      fetchFn,
      sideChannelFetch,
      strict
    });
    this.paymentMakers = new Map(Object.entries(paymentMakers));
    this.sideChannelFetch = sideChannelFetch;
  }

  protected handleAuthFailure = async (oauthError: OAuthAuthenticationRequiredError): Promise<string> => {
    console.log('entering handleAuthFailure');
    const authorizationUrl = await this.oauthClient.makeAuthorizationUrl(
      oauthError.url, 
      oauthError.resourceServerUrl
    );
    console.log('authorizationUrl', authorizationUrl);

    if (authorizationUrl.searchParams.get('payMcp') !== '1') {
      console.log(`PayMCP: authorization url was not a PayMcp url, aborting: ${authorizationUrl}`);
      throw oauthError;
    }

    const requestedNetwork = authorizationUrl.searchParams.get('network');
    if (!requestedNetwork) {
      throw new Error(`Payment network not provided`);
    }

    const destination = authorizationUrl.searchParams.get('destination');
    if (!destination) {
      throw new Error(`destination not provided`);
    }

    let amount = new BigNumber(0);
    if (!authorizationUrl.searchParams.get('amount')) {
      throw new Error(`amount not provided`);
    }
    try{
      amount = new BigNumber(authorizationUrl.searchParams.get('amount')!);
    } catch (e) {
      throw new Error(`Invalid amount ${authorizationUrl.searchParams.get('amount')}`);
    }

    const currency = authorizationUrl.searchParams.get('currency');
    if (!currency) {
      throw new Error(`Currency not provided`);
    }

    const codeChallenge = authorizationUrl.searchParams.get('code_challenge');
    if (!codeChallenge) {
      throw new Error(`Code challenge not provided`);
    }

    const paymentMaker = this.paymentMakers.get(requestedNetwork);
    if (!paymentMaker) {
      console.log(`PayMCP: payment network ${requestedNetwork} not set up for this server (available: ${Array.from(this.paymentMakers.keys()).join(', ')}) - re-throwing so it can be chained to the caller (if any)`);
      throw oauthError;
    }

    console.log('paymentmaker');
    const paymentId = await paymentMaker.makePayment(amount, currency, destination, authorizationUrl.searchParams.get('resourceName') || undefined);
    console.log(`PayMCP: made payment of ${amount} ${currency} on ${requestedNetwork}: ${paymentId}`);

    const signature = await paymentMaker.signBySource(codeChallenge, paymentId);
    // The authToken is base64 encoded versions of the paymentId and signature, 
    // separate by a :
    //   The signature is calculated over codeChallenge+paymentId in order to 
    // prevent re-use of the token (since the codeChallenge is going to be unique per auth request).
    const authToken = Buffer.from(`${paymentId}:${signature}`).toString('base64');

    // Make a fetch call to the authorization URL with the payment ID
    console.log(`PayMCP: fetching authorization URL ${authorizationUrl.toString()} with auth token ${authToken}`);
    // redirect=false is a hack
    // The OAuth spec calls for the authorization url to return with a redirect, but fetch
    // on mobile will automatically follow the redirect (it doesn't support the redirect=manual option)
    // We want the redirect URL so we can extract the code from it, not the contents of the 
    // redirect URL (which might not even exist for agentic paymcp clients)
    //   So paymcp servers are set up to instead return a 200 with the redirect URL in the body
    // if we pass redirect=false.
    const response = await this.sideChannelFetch(authorizationUrl.toString()+'&redirect=false', {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });
    // Check if we got a redirect response (301, 302, etc.) in case the server follows 
    // the OAuth spec
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('Location');
      if (location) {
        console.log(`PayMCP: got redirect authorization code response - redirect to ${location}`);
        return location;
      } else {
        console.log(`PayMCP: got redirect authorization code response, but no redirect URL in Location header`);
      }
    }
    // Handle the non-standard paymcp redirect=false hack
    if (response.ok) {
      // Handle the redirect manually
      const body = await response.json();
      const redirectUrl = body.redirect;
      if (redirectUrl) {
        console.log(`PayMCP: got response.ok authorization code response - redirect to ${redirectUrl}`);
        return redirectUrl;
      } else {
        console.log(`PayMCP: got authorization code response with response.ok, but no redirect URL in body`);
      }
    }

    // If we didn't get a redirect, throw an error
    throw new Error(`Expected redirect response from authorization URL, got ${response.status}`);
  }

  fetch: FetchLike = async (url, init) => {
    try {
      // Try to fetch the resource
      return await this.oauthClient.fetch(url, init);
    } catch (error: unknown) {
      console.log('fetch error', error);
      // If we get an OAuth authentication required error, handle it
      if (error instanceof OAuthAuthenticationRequiredError) {
        console.log(`OAuth authentication required - PayMCP client starting payment flow for resource metadata ${error.resourceServerUrl}`);
        // Get the redirect URL for authentication
        const redirectUrl = await this.handleAuthFailure(error);
        console.log('redirectUrl', redirectUrl);

        // Handle the OAuth callback
        await this.oauthClient.handleCallback(redirectUrl);
        console.log('handleCallback done');

        // Retry the request once - we should be auth'd now
        return await this.oauthClient.fetch(url, init);
      }
      
      // If it's not an authentication error, rethrow
      throw error;
    }
  }
} 