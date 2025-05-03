import { BigNumber } from 'bignumber.js';

export interface PaymentMaker {
  makePayment: (amount: BigNumber, currency: string, receiver: string) => Promise<string>;
  signBySource: (requestId: string, message: string) => Promise<string>;
}
