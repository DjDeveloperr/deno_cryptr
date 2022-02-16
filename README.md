# deno_cryptr

Port of https://github.com/MauriceButler/cryptr to Web Crypto API.

```ts
const cryptr = new Cryptr("secret");

const encrypted = await cryptr.encrypt("my secret message");
const decrypted = await cryptr.decrypt(encrypted);
console.log(decrypted); // my secret message
```

TODO: use 16 bytes IV for compatibility with Node Cryptr.
Currently Deno Web Crypto does not support it, so we use 12 bytes.

Another notable difference in API is Deno Cryptr is async.

## License

MIT licensed. All rights reserved.

Copyright 2022 © DjDeveloperr
