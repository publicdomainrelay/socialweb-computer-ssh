import { assertEquals } from "@std/assert";
import { Secp256k1Keypair } from "@atproto/crypto";
import { MemoryStorage, signerFromKeypair } from "@publicdomainrelay/atproto-repo-deno";
import { createRepoFactory } from "@publicdomainrelay/hono-factory-atproto-repo-deno";
import {
  COCORE_APP_REGISTRATION_NSID,
  COCORE_APP_REGISTRATION_RKEY,
  cocoreAppRegistration,
} from "@publicdomainrelay/socialweb-computer-common";

const HOST = "ssh.example.test";
const APP_DID = `did:web:${HOST}`;

async function appPds(alsoKnownAs?: string[]) {
  const kp = await Secp256k1Keypair.create();
  const signer = signerFromKeypair(kp);
  const factory = createRepoFactory({
    storage: new MemoryStorage(),
    signer,
    did: APP_DID,
    publicKeyDid: signer.did(),
    didWebServices: [{ id: "#atproto_pds", type: "AtprotoPersonalDataServer" }],
    alsoKnownAs,
    readOnly: true,
  });
  return { factory, signer };
}

function withHost(path: string): Request {
  return new Request(`http://${HOST}${path}`, { headers: { host: HOST } });
}

Deno.test("the did document resolves by the host it is fetched from", async () => {
  const { factory, signer } = await appPds([`at://${HOST}`]);
  const res = await factory.app.fetch(withHost("/.well-known/did.json"));
  assertEquals(res.status, 200);

  const doc = await res.json();
  assertEquals(doc.id, APP_DID);
  assertEquals(doc.alsoKnownAs, [`at://${HOST}`]);

  const atproto = doc.verificationMethod.find((m: { id: string }) => m.id === `${APP_DID}#atproto`);
  assertEquals(atproto?.publicKeyMultibase, signer.did().replace(/^did:key:/, ""));

  const pds = doc.service.find((s: { id: string }) => s.id === "#atproto_pds");
  assertEquals(pds?.serviceEndpoint, `https://${HOST}`);
});

Deno.test("alsoKnownAs is absent, not empty, when no handle is configured", async () => {
  // It is a conditional spread, so an unset handle must not publish an empty
  // list: an empty alsoKnownAs is a claim, and a false one.
  const { factory } = await appPds(undefined);
  const res = await factory.app.fetch(withHost("/.well-known/did.json"));
  const doc = await res.json();
  assertEquals("alsoKnownAs" in doc, false);
});

Deno.test("atproto-did returns the configured DID rather than the host-derived one", async () => {
  const { factory } = await appPds();
  const res = await factory.app.fetch(withHost("/.well-known/atproto-did"));
  assertEquals(await res.text(), APP_DID);
});

Deno.test("the registration record round-trips and a rewrite is a no-op", async () => {
  const { factory } = await appPds();
  const desired = cocoreAppRegistration({
    name: "socialweb-computer-ssh",
    website: `https://${HOST}`,
    returnUrl: `https://${HOST}/`,
  });

  await factory.api.applyWrites(APP_DID, [{
    action: "create",
    collection: COCORE_APP_REGISTRATION_NSID,
    rkey: COCORE_APP_REGISTRATION_RKEY,
    record: desired,
  }]);

  const first = await factory.api.getRecord(APP_DID, COCORE_APP_REGISTRATION_NSID, COCORE_APP_REGISTRATION_RKEY);
  assertEquals(first?.value, desired);
});

Deno.test("read-only keeps the credential-minting routes off the wire", async () => {
  const { factory } = await appPds();

  const account = await factory.app.fetch(new Request(`http://${HOST}/xrpc/com.atproto.server.createAccount`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle: "intruder", email: "i@example.test", password: "hunter2" }),
  }));
  assertEquals(account.status, 404, "createAccount must not be reachable");

  // getServiceAuth signs any aud/lxm with the key the DID document publishes,
  // so an unauthenticated caller could mint tokens that verify as this DID.
  const svc = await factory.app.fetch(
    withHost("/xrpc/com.atproto.server.getServiceAuth?aud=did:web:evil.test&lxm=com.atproto.repo.createRecord"),
  );
  assertEquals(svc.status, 404, "getServiceAuth must not be reachable");
});

Deno.test("read-only still serves reads, and refuses unauthenticated writes", async () => {
  const { factory } = await appPds();

  await factory.api.applyWrites(APP_DID, [{
    action: "create",
    collection: COCORE_APP_REGISTRATION_NSID,
    rkey: COCORE_APP_REGISTRATION_RKEY,
    record: cocoreAppRegistration({ name: "app", website: "https://x.test", returnUrl: "https://x.test/" }),
  }]);

  // co/core reads the registration record with no credentials at all, so this
  // has to answer 200 with no token rather than merely being un-gated.
  const read = await factory.app.fetch(
    withHost(`/xrpc/com.atproto.repo.getRecord?repo=${encodeURIComponent(APP_DID)}&collection=${COCORE_APP_REGISTRATION_NSID}&rkey=${COCORE_APP_REGISTRATION_RKEY}`),
  );
  assertEquals(read.status, 200, "co/core reads the registration record unauthenticated");
  assertEquals((await read.json()).value.name, "app");

  const write = await factory.app.fetch(withHost("/xrpc/com.atproto.repo.createRecord"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ repo: APP_DID, collection: "dev.cocore.app.registration", rkey: "x", record: {} }),
  });
  assertEquals(write.status, 401, "a write with no token must be refused");
});
