
import { siv } from '@noble/ciphers/aes';
import { randomBytes, managedNonce } from '@noble/ciphers/webcrypto';

const aes256siv = managedNonce(siv);

export const AEAD_ALGO_NAME = "aes-256-gcm-siv";

export function encrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (key.length !== 32) {
        throw new RangeError("AES-256-SIV key must be 32 bytes");
    }
    return aes256siv(key).encrypt(plaintext);
}

export function decrypt(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    if (key.length !== 32) {
        throw new RangeError("AES-256-SIV key must be 32 bytes");
    }
    return aes256siv(key).decrypt(ciphertext);
}
