import * as hex from "https://deno.land/std@0.125.0/encoding/hex.ts";

const IV_LENGTH = 12;
const SALT_LENGTH = 64;

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
        hash: "SHA-256",
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

    const encrypted = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new Uint8Array(),
      },
      key,
      new TextEncoder().encode(text),
    );

    const result = new Uint8Array(
      SALT_LENGTH + IV_LENGTH + encrypted.byteLength,
    );
    result.set(salt, 0);
    result.set(iv, SALT_LENGTH);
    result.set(new Uint8Array(encrypted), SALT_LENGTH + IV_LENGTH);

    return new TextDecoder().decode(hex.encode(result));
  }

  async decrypt(text: string): Promise<string> {
    const data = hex.decode(new TextEncoder().encode(text));

    const salt = data.subarray(0, SALT_LENGTH);
    const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
    const encrypted = data.subarray(SALT_LENGTH + IV_LENGTH);

    const key = await this.#getKey(salt);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: new Uint8Array(),
      },
      key,
      encrypted,
    );

    return new TextDecoder().decode(new Uint8Array(decrypted));
  }
}
