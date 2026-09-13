import { Buffer } from "node:buffer";
import { createHmac, timingSafeEqual } from "node:crypto";
import { createFactory } from "@hono/hono/factory";
import { getCookie, setCookie } from "@hono/hono/cookie";
import type { ServerOAuth } from "@publicdomainrelay/socialweb-computer-oauth-atproto";
import {
  BADGE_BLUE_KEYS_NSID,
  REQUESTER_ASSOCIATE_SERVICE,
  isRequesterAssociation,
  splitSshPublicKey,
} from "@publicdomainrelay/socialweb-computer-common";

export interface OAuthWebFactoryOptions {
  oauth: ServerOAuth;
  cookieSecret: string;
  clientMetadataPath?: string;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

export function signAccountCookie(did: string, secret: string): string {
  return `${did}.${createHmac("sha256", secret).update(did).digest("hex")}`;
}

export function readAccountCookie(value: string | undefined, secret: string): string | null {
  if (!value) return null;
  const split = value.lastIndexOf(".");
  if (split <= 0) return null;
  const did = value.slice(0, split);
  const expected = Buffer.from(signAccountCookie(did, secret));
  const actual = Buffer.from(value);
  if (expected.length !== actual.length) return null;
  return timingSafeEqual(expected, actual) ? did : null;
}

const ACCOUNT_COOKIE = "account_did";

function html(body: string): string {
  return `<!doctype html><meta charset="utf-8"><title>socialweb-computer-ssh</title>${body}`;
}

function escape(value: string): string {
  return value.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] ?? c);
}

export function createOAuthWebFactory(opts: OAuthWebFactoryOptions) {
  const { oauth } = opts;
  const clientMetadataPath = opts.clientMetadataPath ?? "/oauth-client-metadata.json";
  const log = opts.log ?? (() => {});
  const session = (cookie: string | undefined): string | null => readAccountCookie(cookie, opts.cookieSecret);

  function keyRows(records: Array<{ uri: string; rkey: string; value: Record<string, unknown> }>, did: string): string {
    const rows = records.filter((r) => isRequesterAssociation(r.value, did));
    if (rows.length === 0) return "<p>No SSH keys registered.</p>";
    return `<ul>${rows.map((r) => {
      const label = typeof r.value.name === "string" ? r.value.name : r.value.keyId;
      return `<li><code>${escape(String(label))}</code> <form method="post" action="/keys/delete" style="display:inline">
        <input type="hidden" name="rkey" value="${escape(r.rkey)}"><button>remove</button></form></li>`;
    }).join("")}</ul>`;
  }

  return createFactory({
    initApp: (app) => {
      app.get(clientMetadataPath, (c) => c.json(oauth.clientMetadata()));

      app.get("/", async (c) => {
        const did = session(getCookie(c, ACCOUNT_COOKIE));
        if (!did) {
          return c.html(html(`<h1>socialweb-computer-ssh</h1>
            <form method="get" action="/oauth/login">
              <input name="handle" placeholder="handle or DID" required>
              <button>sign in with AT Protocol</button>
            </form>`));
        }
        const records = await oauth.listRecords(did, BADGE_BLUE_KEYS_NSID);
        return c.html(html(`<h1>socialweb-computer-ssh</h1>
          <p>Signed in as <code>${escape(did)}</code></p>
          <h2>SSH keys</h2>
          ${keyRows(records, did)}
          <h2>Add a key</h2>
          <form method="post" action="/keys">
            <input name="name" placeholder="label" required>
            <textarea name="key" placeholder="ssh-ed25519 AAAA... comment" required></textarea>
            <button>register</button>
          </form>`));
      });

      app.get("/oauth/login", async (c) => {
        const handle = c.req.query("handle");
        if (!handle) return c.html(html("<p>missing handle</p>"), 400);
        const url = await oauth.authorize(handle);
        log("oauth_login", { handle });
        return c.redirect(url);
      });

      app.get("/oauth/callback", async (c) => {
        const params = new URL(c.req.url).searchParams;
        const { did } = await oauth.callback(params);
        setCookie(c, ACCOUNT_COOKIE, signAccountCookie(did, opts.cookieSecret), {
          path: "/",
          httpOnly: true,
          sameSite: "Lax",
          maxAge: 3600,
        });
        log("oauth_callback", { did });
        return c.redirect("/");
      });

      app.post("/keys", async (c) => {
        const did = session(getCookie(c, ACCOUNT_COOKIE));
        if (!did) return c.html(html("<p>not signed in</p>"), 401);
        const form = await c.req.formData();
        const key = String(form.get("key") ?? "");
        const name = String(form.get("name") ?? "");
        const parsed = splitSshPublicKey(key);
        if (!parsed) return c.html(html("<p>not an OpenSSH public key</p>"), 400);
        await oauth.createRecord(did, BADGE_BLUE_KEYS_NSID, {
          $type: BADGE_BLUE_KEYS_NSID,
          keyId: `${parsed.algo} ${parsed.key}`,
          name,
          challenge: did,
          service: REQUESTER_ASSOCIATE_SERVICE,
          createdAt: new Date().toISOString(),
        });
        log("key_registered", { did, name });
        return c.redirect("/");
      });

      app.post("/keys/delete", async (c) => {
        const did = session(getCookie(c, ACCOUNT_COOKIE));
        if (!did) return c.html(html("<p>not signed in</p>"), 401);
        const form = await c.req.formData();
        await oauth.deleteRecord(did, BADGE_BLUE_KEYS_NSID, String(form.get("rkey") ?? ""));
        return c.redirect("/");
      });
    },
  });
}
