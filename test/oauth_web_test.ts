import { assertEquals } from "@std/assert";
import { createOAuthWebFactory } from "@publicdomainrelay/hono-factory-socialweb-computer-oauth";
import { BADGE_BLUE_KEYS_NSID, REQUESTER_ASSOCIATE_SERVICE } from "@publicdomainrelay/socialweb-computer-common";
import type { RepoRecord, ServerOAuth } from "@publicdomainrelay/socialweb-computer-oauth-atproto";

const DID = "did:plc:webuser";

interface Written {
  collection: string;
  record: Record<string, unknown>;
}

function stubOAuth(): { oauth: ServerOAuth; written: Written[]; deleted: string[] } {
  const written: Written[] = [];
  const deleted: string[] = [];
  const stored: RepoRecord[] = [{
    uri: `at://${DID}/${BADGE_BLUE_KEYS_NSID}/existing`,
    cid: "cid",
    rkey: "existing",
    value: { keyId: "ssh-ed25519 OLD", name: "laptop", challenge: DID, service: REQUESTER_ASSOCIATE_SERVICE },
  }];
  const oauth: ServerOAuth = {
    clientMetadata: () => ({ client_id: "http://localhost", scope: "atproto" }),
    authorize: async (identifier) => `https://auth.test/authorize?login_hint=${identifier}`,
    callback: async () => ({ did: DID }),
    accountFor: async () => ({ did: DID, handle: "alice.test", pds: "https://pds.test" }),
    listRecords: async () => stored,
    createRecord: async (_did, collection, record) => {
      written.push({ collection, record });
      const rec = { uri: `at://${DID}/${collection}/new`, cid: "cid", rkey: "new", value: record };
      stored.push(rec);
      return rec;
    },
    deleteRecord: async (_did, _collection, rkey) => {
      deleted.push(rkey);
    },
  };
  return { oauth, written, deleted };
}

function app() {
  const { oauth, written, deleted } = stubOAuth();
  return { handler: createOAuthWebFactory({ oauth }).createApp().fetch, written, deleted };
}

Deno.test("oauth web serves client metadata", async () => {
  const { handler } = app();
  const res = await handler(new Request("http://localhost/oauth-client-metadata.json"));
  assertEquals(res.status, 200);
  assertEquals((await res.json()).client_id, "http://localhost");
});

Deno.test("oauth web redirects login to the auth server", async () => {
  const { handler } = app();
  const res = await handler(new Request("http://localhost/oauth/login?handle=alice.test"), { redirect: "manual" });
  assertEquals(res.status, 302);
  assertEquals(res.headers.get("location"), "https://auth.test/authorize?login_hint=alice.test");
});

Deno.test("oauth web callback sets the account cookie", async () => {
  const { handler } = app();
  const res = await handler(new Request("http://localhost/oauth/callback?code=x&state=y"), { redirect: "manual" });
  assertEquals(res.status, 302);
  assertEquals(res.headers.get("location"), "/");
  assertEquals(res.headers.getSetCookie()[0].startsWith(`account_did=${encodeURIComponent(DID)}`), true);
});

Deno.test("oauth web lists registered keys for the signed-in account", async () => {
  const { handler } = app();
  const res = await handler(
    new Request("http://localhost/", { headers: { cookie: `account_did=${DID}` } }),
  );
  const body = await res.text();
  assertEquals(body.includes("laptop"), true);
  assertEquals(body.includes(`/keys/delete`), true);
});

Deno.test("oauth web registers an ssh key as a requester_associate record", async () => {
  const { handler, written } = app();
  const form = new FormData();
  form.set("name", "desk");
  form.set("key", "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAI example@host\n");
  const res = await handler(
    new Request("http://localhost/keys", { method: "POST", body: form, headers: { cookie: `account_did=${DID}` } }),
    { redirect: "manual" },
  );
  assertEquals(res.status, 302);
  assertEquals(written.length, 1);
  assertEquals(written[0].collection, BADGE_BLUE_KEYS_NSID);
  assertEquals(written[0].record.keyId, "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAI");
  assertEquals(written[0].record.name, "desk");
  assertEquals(written[0].record.challenge, DID);
  assertEquals(written[0].record.service, REQUESTER_ASSOCIATE_SERVICE);
});

Deno.test("oauth web rejects a malformed key", async () => {
  const { handler, written } = app();
  const form = new FormData();
  form.set("name", "desk");
  form.set("key", "not-a-key");
  const res = await handler(
    new Request("http://localhost/keys", { method: "POST", body: form, headers: { cookie: `account_did=${DID}` } }),
  );
  assertEquals(res.status, 400);
  assertEquals(written.length, 0);
});

Deno.test("oauth web refuses key writes without a session", async () => {
  const { handler, written } = app();
  const form = new FormData();
  form.set("name", "desk");
  form.set("key", "ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAI");
  const res = await handler(new Request("http://localhost/keys", { method: "POST", body: form }));
  assertEquals(res.status, 401);
  assertEquals(written.length, 0);
});

Deno.test("oauth web deletes a key by rkey", async () => {
  const { handler, deleted } = app();
  const form = new FormData();
  form.set("rkey", "existing");
  const res = await handler(
    new Request("http://localhost/keys/delete", { method: "POST", body: form, headers: { cookie: `account_did=${DID}` } }),
    { redirect: "manual" },
  );
  assertEquals(res.status, 302);
  assertEquals(deleted, ["existing"]);
});
