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
});
