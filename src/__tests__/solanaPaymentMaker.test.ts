import { describe, it, expect } from 'vitest';
import { SolanaPaymentMaker } from '../solanaPaymentMaker';
import { Keypair } from "@solana/web3.js";
import bs58 from "bs58";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";

describe('solanaPaymentMaker.signBySource', () => {
  it('should sign a payment by the source', async () => {
    // This test is mainly here to force someone to read this if they change the signing,
    // because you'll also need to account for that on the server side
    const keypair = Keypair.generate();
    const paymentMaker = new SolanaPaymentMaker('https://example.com', bs58.encode(keypair.secretKey));
    const paymentId = 'test-payment-id';
    const requestId = 'test-request-id';

    const messageBytes = naclUtil.decodeUTF8(requestId + paymentId);
    const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
    const expected = Buffer.from(signature).toString('base64');

    const res = await paymentMaker.signBySource(requestId, paymentId);
    expect(res).toBe(expected);
  });
});