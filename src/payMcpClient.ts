import type { PaymentMaker, FetchLike, OAuthDb } from './types.js';
import { OAuthClient, OAuthAuthenticationRequiredError } from './oAuthClient.js';
import { BigNumber } from 'bignumber.js';

export class PayMcpClient {
  protected oauthClient: OAuthClient;
  protected paymentMakers: Map<string, PaymentMaker>;
  protected fetchFn: FetchLike;

  constructor(userId: string, db: OAuthDb, callbackUrl: string, isPublic: boolean, paymentMakers: {[key: string]: PaymentMaker}, fetchFn: FetchLike = fetch, strict: boolean = true) {
    this.oauthClient = new OAuthClient(userId, db, callbackUrl, isPublic, fetchFn, strict);
    this.paymentMakers = new Map(Object.entries(paymentMakers));
    this.fetchFn = fetchFn;
  }

  protected handleAuthFailure = async (oauthError: OAuthAuthenticationRequiredError): Promise<string> => {
    const authorizationUrl = await this.oauthClient.makeAuthorizationUrl(oauthError.resourceServerUrl);

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

    const paymentId = await paymentMaker.makePayment(amount, currency, destination);
    console.log(`PayMCP: made payment of ${amount} ${currency} on ${requestedNetwork}: ${paymentId}`);

    const signature = await paymentMaker.signBySource(codeChallenge, paymentId);
    // The authToken is base64 encoded versions of the paymentId and signature, 
    // separate by a :
    //   The signature is calculated over codeChallenge+paymentId in order to 
    // prevent re-use of the token (since the codeChallenge is going to be unique per auth request).
    const authToken = Buffer.from(`${paymentId}:${signature}`).toString('base64');

    // Make a fetch call to the authorization URL with the payment ID
    console.log(`PayMCP: fetching authorization URL ${authorizationUrl.toString()} with auth token ${authToken}`);
    const response = await this.fetchFn(authorizationUrl.toString(), {
      method: 'GET',
      redirect: 'manual',
      headers: {
        'Authorization': `Bearer ${authToken}`
      }
    });

    // Check if we got a redirect response (301, 302, etc.)
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('Location');
      if (location) {
        console.log(`PayMCP: got authorization code response - redirect to ${location}`);
        return location;
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
      // If we get an OAuth authentication required error, handle it
      if (error instanceof OAuthAuthenticationRequiredError) {
        console.log(`OAuth authentication required - PayMCP client starting payment flow for ${error.resourceServerUrl}`);
        // Get the redirect URL for authentication
        const redirectUrl = await this.handleAuthFailure(error);
        
        // Handle the OAuth callback
        await this.oauthClient.handleCallback(redirectUrl);
        
        // Retry the request once - we should be auth'd now
        return await this.oauthClient.fetch(url, init);
      }
      
      // If it's not an authentication error, rethrow
      throw error;
    }
  }
} 