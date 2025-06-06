import type { BigNumber } from 'bignumber.js';

export interface PaymentMaker {
  makePayment: (amount: BigNumber, currency: string, receiver: string, resourceName?: string) => Promise<string>;
  signBySource: (requestId: string, message: string) => Promise<string>;
}

export type ClientCredentials = {
  clientId: string,
  clientSecret: string,
  redirectUri: string
};

export type PKCEValues = {
  codeVerifier: string,
  codeChallenge: string,
  resourceUrl: string,
  url: string
};

export type AccessToken = {
  accessToken: string,
  refreshToken?: string,
  expiresAt?: number,
  resourceUrl: string
};

export interface OAuthGlobalDb {
  getClientCredentials(serverUrl: string): Promise<ClientCredentials | null>;
  saveClientCredentials(serverUrl: string, credentials: ClientCredentials): Promise<void>;
  close(): Promise<void>;
}

export interface OAuthDb extends OAuthGlobalDb {
  getPKCEValues(userId: string, state: string): Promise<PKCEValues | null>;
  savePKCEValues(userId: string, state: string, values: PKCEValues): Promise<void>;
  getAccessToken(userId: string, url: string): Promise<AccessToken | null>;
  saveAccessToken(userId: string, url: string, token: AccessToken): Promise<void>;
}

export type TokenData = {
  active: boolean,
  scope?: string,
  sub?: string,
  aud?: string|string[],
}

export type FetchLike = (url: string, init?: RequestInit) => Promise<Response>;