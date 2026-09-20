// PDS access for the signed-in account, and the session handoff to the server.
//
// The repo calls are written out rather than going through @atproto/api's
// Agent. That is deliberate and matches did-key-associator's client-side flow:
// the browser OAuth above has to generate the DPoP key with extractable:true so
// the private JWK stays available, because this page's whole job is to hand the
// session (DPoP key included) to the SSH server. A session object from the
// official browser client keeps that key private by design, so it cannot.
//
// What goes on the wire is the ordinary thing: a DPoP-bound access token on
// com.atproto.repo.{listRecords,createRecord,deleteRecord}, which is exactly
// what the spec requires of any client writing to a repo on a user's behalf.

import { authServerMetadata, createDpopProof } from './atproto-oauth.js';

const SESSION_KEY = 'swc-session';

export function loadSession() {
  const raw = localStorage.getItem(SESSION_KEY);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw);
    return session && session.accessJwt && session.dpopPrivateJwk ? session : null;
  } catch {
    return null;
  }
}

export function saveSession(session) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession() {
  localStorage.removeItem(SESSION_KEY);
}

async function importKeys(session) {
  const clean = (jwk) => {
    const { key_ops, ext, use, alg, ...rest } = jwk;
    return rest;
  };
  return {
    privateKey: await crypto.subtle.importKey(
      'jwk', clean(session.dpopPrivateJwk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'],
    ),
    publicKey: await crypto.subtle.importKey(
      'jwk', clean(session.dpopPublicJwk), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'],
    ),
  };
}

// The refresh token rotates on every use, so two refreshes racing would spend it
// twice and one would fail -- and a refresh presented twice can be treated as
// replay. One in flight at a time, shared across every call on the page.
let refreshInFlight = null;

/**
 * Find the token endpoint for a session that does not carry one.
 *
 * The account's PDS is not its authorization server, and the two are usually on
 * different hosts -- a bsky account's PDS is some `*.host.bsky.network` while its
 * authorization server is `bsky.social`. The chain is the one the login flow
 * follows: the PDS advertises the authorization servers it trusts, and each of
 * those publishes its own metadata. Guessing that the PDS serves the metadata
 * itself answers 404.
 *
 * Only reached by a session deposited before the endpoint was recorded on it.
 */
async function discoverTokenEndpoint(pds) {
  const base = pds.replace(/\/+$/, '');
  const resource = await fetch(`${base}/.well-known/oauth-protected-resource`);
  if (!resource.ok) throw new Error(`PDS metadata: ${resource.status}`);
  const authServer = (await resource.json()).authorization_servers?.[0];
  if (!authServer) throw new Error('PDS advertises no authorization server');
  const meta = await authServerMetadata(authServer);
  if (!meta.token_endpoint) throw new Error('authorization server metadata carries no token_endpoint');
  return meta.token_endpoint;
}

/**
 * Exchange the refresh token for a fresh access token, in place.
 *
 * atproto's authorization server is the account's own PDS, so the refresh is an
 * ordinary RFC 6749 refresh_token grant against its token endpoint -- DPoP-bound
 * to the same key the session was issued to, because the key is what the tokens
 * are bound to and a proof from any other key is refused.
 *
 * Both tokens are replaced: the new refresh token supersedes the old one, so
 * dropping it would strand the session at the next expiry.
 */
async function refreshAccessToken(session) {
  if (refreshInFlight) return await refreshInFlight;

  refreshInFlight = (async () => {
    const keys = await importKeys(session);
    const tokenEndpoint = session.tokenEndpoint || await discoverTokenEndpoint(session.pds);
    session.tokenEndpoint = tokenEndpoint;

    const send = async (nonce) => fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        // No ath: RFC 9449 wants the access-token hash only when a proof travels
        // alongside an access token, and here there is none to hash.
        DPoP: await createDpopProof(keys, session.dpopPublicJwk, 'POST', tokenEndpoint, nonce),
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: session.refreshJwt,
        client_id: session.clientId,
      }).toString(),
    });

    let res = await send(session.dpopNonce || null);
    if (res.status === 400 && (await res.clone().text()).includes('use_dpop_nonce')) {
      const nonce = res.headers.get('DPoP-Nonce');
      if (!nonce) throw new Error('token endpoint asked for a DPoP nonce but sent none');
      session.dpopNonce = nonce;
      res = await send(nonce);
    }
    if (!res.ok) throw new Error(`token refresh: ${res.status} ${await res.text()}`);

    const tokens = await res.json();
    if (!tokens.access_token) throw new Error('token refresh returned no access_token');
    session.accessJwt = tokens.access_token;
    if (tokens.refresh_token) session.refreshJwt = tokens.refresh_token;
    saveSession(session);
  })().finally(() => { refreshInFlight = null; });

  return await refreshInFlight;
}

/**
 * Run a request that carries the session, refreshing once if it comes back 401.
 *
 * Exported because the pairing endpoints are reached without going through the
 * repo client -- they are this deployment's own routes -- yet they carry the
 * same session to the same server, and the server proves a deposit with a live
 * PDS call of its own. A client that cannot renew its token is a client that
 * stops working once the access token ages out, whichever client it is.
 */
export async function withRefresh(session, send) {
  let res = await send();
  if (res.status === 401) {
    await refreshAccessToken(session);
    res = await send();
  }
  return res;
}

// A request carrying the session, retrying once for a DPoP nonce. Kept separate
// from the refresh retry because the two are independent: a nonce challenge is
// not an expiry, and an expiry is not a nonce challenge.
async function sendWithNonce(session, keys, method, url, body) {
  const send = async (nonce) => fetch(url, {
    method,
    headers: {
      ...(body ? { 'content-type': 'application/json' } : {}),
      Authorization: `DPoP ${session.accessJwt}`,
      DPoP: await createDpopProof(keys, session.dpopPublicJwk, method, url, nonce, session.accessJwt),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  let res = await send(session.dpopNonce || null);
  if ((res.status === 400 || res.status === 401) && (await res.clone().text()).includes('use_dpop_nonce')) {
    const fresh = res.headers.get('DPoP-Nonce');
    if (fresh) {
      session.dpopNonce = fresh;
      saveSession(session);
      res = await send(fresh);
    }
  }
  return res;
}

export function createPdsClient(session) {
  const pds = session.pds.replace(/\/+$/, '');

  async function call(nsid, { method = 'GET', params, body } = {}) {
    const keys = await importKeys(session);
    const url = new URL(`${pds}/xrpc/${nsid}`);
    for (const [k, v] of Object.entries(params || {})) url.searchParams.set(k, v);

    const res = await withRefresh(session, () => sendWithNonce(session, keys, method, url.toString(), body));
    if (!res.ok) throw new Error(`${nsid}: ${res.status} ${await res.text()}`);
    return res.status === 204 ? null : await res.json();
  }

  return { call, pds, did: session.userDid };
}

export async function listRecords(client, collection, { limit = 100 } = {}) {
  const out = [];
  let cursor;
  do {
    const params = { repo: client.did, collection, limit: String(limit) };
    if (cursor) params.cursor = cursor;
    const body = await client.call('com.atproto.repo.listRecords', { params });
    for (const rec of body.records || []) out.push(rec);
    cursor = body.cursor || null;
  } while (cursor);
  return out;
}

export async function createRecord(client, collection, record) {
  const rkey = tid();
  const body = await client.call('com.atproto.repo.createRecord', {
    method: 'POST',
    body: { repo: client.did, collection, rkey, record, validate: false },
  });
  return { uri: body.uri, cid: body.cid, rkey };
}

export async function deleteRecord(client, collection, rkey) {
  await client.call('com.atproto.repo.deleteRecord', {
    method: 'POST',
    body: { repo: client.did, collection, rkey },
  });
}

// TID, the record key format atproto uses for repo records.
function tid() {
  const ENCODE = '234567abcdefghijklmnopqrstuvwxyz';
  let str = '';
  let n = BigInt(Date.now()) * 1000n + BigInt(Math.floor(Math.random() * 1000));
  for (let i = 0; i < 13; i++) {
    str = ENCODE[Number(n & 31n)] + str;
    n >>= 5n;
  }
  return str;
}

// Deposit the session with the SSH server, which leases it into a temp dir for
// request-vm-ssh. The server only ever needs a session to hand to the requester
// process; it writes nothing to the account itself.
export async function depositSession(session) {
  const res = await fetch('/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(session),
  });
  if (!res.ok) throw new Error(`session deposit: ${res.status} ${await res.text()}`);
  return await res.json();
}
