import { Cryptr } from "./mod.ts";
import { assertEquals } from "https://deno.land/std@0.125.0/testing/asserts.ts";

Deno.test("cryptr", async (t) => {
  const cryptr = new Cryptr("secret");

  let encrypted!: string;

  await t.step("encrypt", async () => {
    encrypted = await cryptr.encrypt("hello world");
  });

  await t.step("decrypt", async () => {
    const decrypted = await cryptr.decrypt(encrypted);
    assertEquals(decrypted, "hello world");
  });

  // Currently does not work because IV length is different
  // in Deno Cryptr it's 12 because of a limitation in Deno Web Crypto
  // while in Node it's 16.
  
  // await t.step("node cryptr compat", async () => {
  //   const cryptr = new Cryptr("myTotalySecretKey");
  //   const decrypted = await cryptr.decrypt(
  //     "e7b75a472b65bc4a42e7b3f78833a4d00040beba796062bf7c13d9533b149e5ec3784813dc20348fdf248d28a2982df85b83d1109623bce45f08238f6ea9bd9bb5f406427b2a40f969802635b8907a0a57944f2c12f334bd081d5143a357c173a611e1b64a",
  //   );
  //   assertEquals(decrypted, "bacon");
  // });
});
