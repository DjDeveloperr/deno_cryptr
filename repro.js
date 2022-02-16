const key = await crypto.subtle.generateKey(
  {
    name: "AES-GCM",
    length: 256,
  },
  false,
  ["encrypt", "decrypt"],
);

const iv = crypto.getRandomValues(new Uint8Array(16));

const msg = "Hello World!";

const encrypted = await crypto.subtle.encrypt(
  {
    name: "AES-GCM",
    iv,
    // additionalData: new Uint8Array(),
  },
  key,
  new TextEncoder().encode(msg),
);

const decrypted = await crypto.subtle.decrypt(
  {
    name: "AES-GCM",
    iv,
    // additionalData: new Uint8Array(),
  },
  key,
  encrypted,
);

console.log(new TextDecoder().decode(decrypted));
