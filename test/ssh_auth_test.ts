import { assertEquals } from "@std/assert";
import { Buffer } from "node:buffer";
// @ts-types="npm:@types/ssh2@^1"
import { utils } from "ssh2";
import { verifyPublicKeySignature } from "@publicdomainrelay/socialweb-computer-ssh-ssh2";
import { splitSshPublicKey } from "@publicdomainrelay/socialweb-computer-common";

const BLOB = Buffer.from("session-id || userauth-request");
const OTHER_BLOB = Buffer.from("a different session");

function signer() {
  for (let attempt = 0; attempt < 20; attempt++) {
    const pair = utils.generateKeyPairSync("ed25519");
    const priv = utils.parseKey(pair.private);
    if (priv instanceof Error) continue;
    const pub = splitSshPublicKey(pair.public);
    if (!pub) continue;
    return { priv, pub };
  }
  throw new Error("ssh2 could not produce a parseable ed25519 key");
}

Deno.test("a publickey probe with no signature is allowed through", () => {
  const { pub } = signer();
  assertEquals(verifyPublicKeySignature(pub, {}), true);
});

Deno.test("a signature over the presented blob verifies", () => {
  const { priv, pub } = signer();
  const signature = priv.sign(BLOB);
  assertEquals(verifyPublicKeySignature(pub, { signature, blob: BLOB }), true);
});

Deno.test("a signature over a different blob is refused", () => {
  const { priv, pub } = signer();
  const signature = priv.sign(OTHER_BLOB);
  assertEquals(verifyPublicKeySignature(pub, { signature, blob: BLOB }), false);
});

Deno.test("another key's signature is refused", () => {
  const { pub } = signer();
  const attacker = signer();
  assertEquals(verifyPublicKeySignature(pub, { signature: attacker.priv.sign(BLOB), blob: BLOB }), false);
});

Deno.test("a garbage signature is refused", () => {
  const { pub } = signer();
  const garbage = new Uint8Array(64).fill(7);
  assertEquals(verifyPublicKeySignature(pub, { signature: garbage, blob: BLOB }), false);
});

Deno.test("a signature with no blob to check it against is refused", () => {
  const { priv, pub } = signer();
  assertEquals(verifyPublicKeySignature(pub, { signature: priv.sign(BLOB) }), false);
});

Deno.test("an unparseable key is refused", () => {
  assertEquals(
    verifyPublicKeySignature({ algo: "ssh-ed25519", key: "not-base64" }, { signature: new Uint8Array(8), blob: BLOB }),
    false,
  );
});
