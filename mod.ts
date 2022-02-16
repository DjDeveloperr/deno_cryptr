import * as hex from "https://deno.land/std@0.125.0/encoding/hex.ts";

// TODO: use 16 byte IV in Deno as well. but right now there seems to be an issue
// in Deno Web Crypto which causes it to throw "Initialization vector length not supported"
// when using 16 byte IV.
// Ref: https://github.com/denoland/deno/issues/13689
const IV_LENGTH = typeof Deno === "object" ? 12 : 16;
const SALT_LENGTH = 64;
const TAG_LENGTH = 16;

const SALT_POSITION = 0;
const IV_POSITION = SALT_POSITION + SALT_LENGTH;
const TAG_POSITION = IV_POSITION + IV_LENGTH;
const CIPHER_POSITION = TAG_POSITION + TAG_LENGTH;

export class Cryptr {
  #secret: Uint8Array;

  constructor(secret: string) {
    this.#secret = new TextEncoder().encode(secret);
  }

  #baseKey?: CryptoKey;

  async #getKey(salt: Uint8Array) {
    const baseKey =
      (this.#baseKey ?? (this.#baseKey = await crypto.subtle.importKey(
        "raw",
        this.#secret,
        "PBKDF2",
        false,
        ["deriveKey", "deriveBits"],
      )));

    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-512",
        salt,
        iterations: 100000,
      },
      baseKey,
      {
        name: "AES-GCM",
        length: 256,
      },
      false,
      ["encrypt", "decrypt"],
    );
  }

  async encrypt(text: string): Promise<string> {
    const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

    const key = await this.#getKey(salt);

    const encrypted = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv,
          additionalData: new Uint8Array(),
          tagLength: TAG_LENGTH * 8,
        },
        key,
        new TextEncoder().encode(text),
      ),
    );

    const cipher = encrypted.subarray(0, encrypted.length - TAG_LENGTH);
    const authTag = encrypted.subarray(encrypted.length - TAG_LENGTH);

    const result = new Uint8Array(
      SALT_LENGTH + IV_LENGTH + encrypted.byteLength,
    );

    result.set(salt, SALT_POSITION);
    result.set(iv, IV_POSITION);
    result.set(authTag, TAG_POSITION);
    result.set(cipher, CIPHER_POSITION);

    return new TextDecoder().decode(hex.encode(result));
  }

  async decrypt(text: string): Promise<string> {
    const data = hex.decode(new TextEncoder().encode(text));

    const salt = data.subarray(SALT_POSITION, SALT_LENGTH);
    const iv = data.subarray(IV_POSITION, IV_POSITION + IV_LENGTH);
    const authTag = data.subarray(TAG_POSITION, TAG_POSITION + TAG_LENGTH);
    const cipher = data.subarray(CIPHER_POSITION);

    const encrypted = new Uint8Array(cipher.length + TAG_LENGTH);
    encrypted.set(cipher);
    encrypted.set(authTag, cipher.length);

    const key = await this.#getKey(salt);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new Uint8Array(),
        tagLength: TAG_LENGTH * 8,
      },
      key,
      encrypted,
    );

    return new TextDecoder().decode(new Uint8Array(decrypted));
  }
}
