import type { PaymentMaker, FetchLike } from './types.js';
import { OAuthClient, OAuthAuthenticationRequiredError } from './oauthClient.js';
import { OAuthClientDb } from './oauthClientDb.js';
import { BigNumber } from 'bignumber.js';

export class PayMcpClient {
  private oauthClient: OAuthClient;
  private paymentMakers: Map<string, PaymentMaker>;

  constructor(db: OAuthClientDb, isPublic: boolean, paymentMakers: {[key: string]: PaymentMaker}, fetchFn: FetchLike = fetch, strict: boolean = true) {
    // We'll always use the paymcp://mcp redirect URI, because this client
    // should never actually require a callback. Instead, we detect the oauth
    // challenge, make a payment, and then directly invoke the oauth flow.
    this.oauthClient = new OAuthClient(db, 'paymcp://mcp', isPublic, fetchFn, strict);
    this.paymentMakers = new Map(Object.entries(paymentMakers));
  }

  private handleAuthFailure = async (oauthError: OAuthAuthenticationRequiredError): Promise<string> => {
    if (oauthError.authorizationUrl.searchParams.get('payMcp') !== '1') {
        console.log(`PayMCP: authorization url was not a PayMcp url, aborting: ${oauthError.authorizationUrl}`);
        throw oauthError;
    }

    const requestedNetwork = oauthError.authorizationUrl.searchParams.get('network');
    if (!requestedNetwork) {
        throw new Error(`Payment network not provided`);
    }

    const paymentMaker = this.paymentMakers.get(requestedNetwork);
    if (!paymentMaker) {
      throw new Error(`Payment network ${requestedNetwork} not found`);
    }

    const destination = oauthError.authorizationUrl.searchParams.get('destination');
    if (!destination) {
        throw new Error(`destination not provided`);
    }

    let amount = new BigNumber(0);
    try{
        amount = new BigNumber(oauthError.authorizationUrl.searchParams.get('amount') ?? '0');
    } catch (e) {
        throw new Error(`Invalid amount ${oauthError.authorizationUrl.searchParams.get('amount')}`);
    }

    const currency = oauthError.authorizationUrl.searchParams.get('currency');
    if (!currency) {
        throw new Error(`Currency not provided`);
    }

    const codeChallenge = oauthError.authorizationUrl.searchParams.get('code_challenge');
    if (!codeChallenge) {
        throw new Error(`Code challenge not provided`);
    }

    const paymentId = await paymentMaker.makePayment(amount, currency, destination);
    console.log(`PayMCP: made payment of ${amount} ${currency} on ${requestedNetwork}: ${paymentId}`);

    const signature = await paymentMaker.signBySource(codeChallenge, paymentId);
    // The authToken is base64 encoded versions of the paymentId and signature, 
    // separate by a :
    //   The signature is calculated over codeChallenge+paymentId in order to 
    // prevent re-use of the token (since the codeChallenge is going to be unique per auth request).
    const authToken = Buffer.from(paymentId).toString('base64') + ':' +
        Buffer.from(signature).toString('base64');

    // Make a fetch call to the authorization URL with the payment ID as a cookie
    const response = await fetch(oauthError.authorizationUrl.toString(), {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${authToken}`
      },
      redirect: 'manual' // Don't automatically follow redirects
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
        console.log('OAuth authentication required - PayMCP client starting payment flow');
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