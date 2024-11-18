
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { scryptAsync } from '@noble/hashes/scrypt';

import * as aes256siv from './aes-256-siv.js';
import * as utf8 from './utf8.js';

export const SCRYPT_N16_R8_P1 = 'scrypt-N16-R8-P1';

function sha256Hkdf(data: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    return hkdf(sha256, data, new Uint8Array(0), info, length); // no salt
}

export class Passphrase {
    readonly #passphrase: string;

    public constructor(passphrase: string) {
        if ('string' != typeof passphrase || passphrase.length < 12) {
            throw new Error("Passphrase must be a string of at least 12 characters");
        }
        this.#passphrase = passphrase;
    }

    public deriveKey(usageTag: PassphraseUsageTag): PassphraseDerivedKey {
        const info = utf8.encode(usageTag.toString());
        const key = sha256Hkdf(utf8.encode(this.#passphrase), info, 32);
        return { usageTag: usageTag.toString(), key };
    }
}

export interface PassphraseDerivedKey {
    readonly usageTag: string;
    readonly key: Uint8Array;
}

export class PassphraseUsageTag {
    public static readonly STORAGE_ENCRYPTION = 'storage-encryption';
    public static readonly SERVER_LOGIN = 'server-login';

    static #validPrefixes = new Set([PassphraseUsageTag.STORAGE_ENCRYPTION, PassphraseUsageTag.SERVER_LOGIN]);

    public readonly type: string;
    public readonly identifier: string;

    private constructor(type: string, identifier: string) {
        if (!PassphraseUsageTag.#validPrefixes.has(type)) {
            throw new Error("Invalid passphrase usage tag");
        }
        this.type = type;
        this.identifier = identifier;
    }

    public toString(): string {
        return `${this.type}:${this.identifier}`;
    }

    public static parse(tag: string): PassphraseUsageTag {
        const [type, identifier] = tag.split(':') as [string, string];
        if (!identifier || !PassphraseUsageTag.#validPrefixes.has(type)) {
            throw new Error("Invalid passphrase usage tag");
        }
        return new PassphraseUsageTag(type, identifier);
    }

    public static forStorageEncryption(username: string): PassphraseUsageTag {
        return new PassphraseUsageTag(PassphraseUsageTag.STORAGE_ENCRYPTION, username);
    }

    public static forServerLogin(host: string): PassphraseUsageTag {
        return new PassphraseUsageTag(PassphraseUsageTag.SERVER_LOGIN, host);
    }
}

export interface PassphraseWrappedKey {
    readonly hashAlgo: string;
    readonly salt: Uint8Array;
    readonly aeadAlgo: string;
    readonly wrappedKey: Uint8Array;
}

export async function wrapKey(username: string, passphrase: Passphrase, key: Uint8Array): Promise<PassphraseWrappedKey> {
    const keyUsage = PassphraseUsageTag.forStorageEncryption(username);
    const derivedKey = passphrase.deriveKey(keyUsage);

    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const keyData = await scryptAsync(derivedKey.key, salt, {
        N: 1 << 16,
        r: 8,
        p: 1,
        dkLen: 32,
    });
    const wrappedKey = aes256siv.encrypt(keyData, key);
    return { hashAlgo: SCRYPT_N16_R8_P1, salt, aeadAlgo: aes256siv.AEAD_ALGO_NAME, wrappedKey };
}

export async function unwrapKey(username: string, passphrase: Passphrase, wrappedKey: PassphraseWrappedKey): Promise<Uint8Array> {
    const keyUsage = PassphraseUsageTag.forStorageEncryption(username);
    const derivedKey = passphrase.deriveKey(keyUsage);

    if (wrappedKey.hashAlgo !== SCRYPT_N16_R8_P1) {
        throw new Error("Unsupported hash algorithm");
    }
    if (wrappedKey.aeadAlgo !== aes256siv.AEAD_ALGO_NAME) {
        throw new Error("Unsupported AEAD algorithm");
    }
    const keyData = await scryptAsync(derivedKey.key, wrappedKey.salt, {
        N: 1 << 16,
        r: 8,
        p: 1,
        dkLen: 32,
    });
    return aes256siv.decrypt(keyData, wrappedKey.wrappedKey);
}
