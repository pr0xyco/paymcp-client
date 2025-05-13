import type { BigNumber } from 'bignumber.js';

export interface PaymentMaker {
  makePayment: (amount: BigNumber, currency: string, receiver: string) => Promise<string>;
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
  resourceServerUrl: string
};

export type AccessToken = {
  accessToken: string,
  refreshToken?: string,
  expiresAt?: number
};

export interface OAuthClientDb {
  getClientCredentials(resourceServerUrl: string): Promise<ClientCredentials | null>;

  saveClientCredentials(
    resourceServerUrl: string,
    credentials: ClientCredentials
  ): Promise<void>;

  getPKCEValues(state: string): Promise<PKCEValues | null>;

  savePKCEValues(
    state: string,
    values: PKCEValues
  ): Promise<void>;

  getAccessToken(resourceServerUrl: string): Promise<AccessToken | null>;

  saveAccessToken(
    resourceServerUrl: string,
    token: AccessToken
  ): Promise<void>;

  close(): Promise<void>;
}

export type TokenData = {
  active: boolean,
  scope?: string,
  sub?: string,
  aud?: string|string[],
}

export type FetchLike = (url: string, init?: {
  method?: string;
  headers?: Record<string, string>;
  body?: any;
}) => Promise<Response>;