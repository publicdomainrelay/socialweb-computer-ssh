import { assertEquals } from "@std/assert";

const WEB = new URL("../web/", import.meta.url).pathname;

async function read(relative: string): Promise<string> {
  return await Deno.readTextFile(new URL(relative, new URL("../web/", import.meta.url)));
}

Deno.test("the web app ships the files the server serves and the page loads", async () => {
  const html = await read("index.html");
  assertEquals(html.includes("/components/swc-app.js"), true);
  assertEquals(html.includes("/styles.css"), true);
  assertEquals(html.includes("no build step") || html.includes("<swc-app>"), true);

  for (const asset of ["styles.css", "components/swc-app.js", "components/swc-key-list.js", "lib/atproto-oauth.js", "lib/pds.js", "generated/oauth-scope.js"]) {
    const stat = await Deno.stat(new URL(asset, new URL("../web/", import.meta.url)));
    assertEquals(stat.isFile, true, `${asset} must exist`);
  }
});

Deno.test("the web app takes its scope from the generated module, not a literal", async () => {
  const app = await read("components/swc-app.js");
  assertEquals(app.includes("./generated/oauth-scope.js") || app.includes("../generated/oauth-scope.js"), true);
  assertEquals(/atproto repo:/.test(app), false, "the scope must not be written into the component");

  const generated = await read("generated/oauth-scope.js");
  assertEquals(generated.includes("DO NOT EDIT"), true);
  assertEquals(generated.includes("export const OAUTH_SCOPE ="), true);
});

Deno.test("the web app runs the flow itself rather than posting credentials to the server", async () => {
  const oauth = await read("lib/atproto-oauth.js");
  assertEquals(oauth.includes("pushed_authorization_request_endpoint"), true);
  assertEquals(oauth.includes("code_challenge_method"), true);
  assertEquals(oauth.includes("dpop+jwt"), true);

  const pds = await read("lib/pds.js");
  // The only thing the page sends the server is the session it obtained.
  assertEquals([...pds.matchAll(/fetch\(\s*['"]\//g)].map((m) => m[0]).length, 1);
  assertEquals(pds.includes("depositSession"), true);
});

Deno.test("the deposited session names the client_id it was issued to", async () => {
  // A refresh token is bound to the client that obtained it, and the server has
  // no other way to learn which client that was: on loopback the page signs in
  // with a `http://localhost?...` virtual metadata document that cannot be
  // reconstructed from the session, and a refresh presented as a different
  // client is rejected. So the session has to carry it, end to end.
  //
  // Source-level, matching this file: there is no seam to inject the agent
  // helper, so the invariant is asserted where it is written.
  const oauth = await read("lib/atproto-oauth.js");
  const payload = oauth.slice(
    oauth.indexOf("session: {"),
    oauth.indexOf("returnTo: pending.returnTo"),
  );
  assertEquals(payload.includes("clientId: pending.clientId"), true, "the page must send its client_id");

  const common = await Deno.readTextFile(
    new URL("../lib/common/socialweb-computer-common/mod.ts", import.meta.url),
  );
  assertEquals(common.includes("clientId?: string"), true, "the session type must carry it");

  const inproc = await Deno.readTextFile(
    new URL("../lib/socialweb-computer-requester-inproc/mod.ts", import.meta.url),
  );
  assertEquals(
    inproc.includes("stored.clientId ?? opts.oauthClientId"),
    true,
    "the requester must refresh as the session's own client",
  );
});
