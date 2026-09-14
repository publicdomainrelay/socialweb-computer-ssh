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

import { createDpopProof } from './atproto-oauth.js';

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

export function createPdsClient(session) {
  const pds = session.pds.replace(/\/+$/, '');

  async function call(nsid, { method = 'GET', params, body } = {}) {
    const keys = await importKeys(session);
    const url = new URL(`${pds}/xrpc/${nsid}`);
    for (const [k, v] of Object.entries(params || {})) url.searchParams.set(k, v);

    const send = async (nonce) => fetch(url.toString(), {
      method,
      headers: {
        ...(body ? { 'content-type': 'application/json' } : {}),
        Authorization: `DPoP ${session.accessJwt}`,
        DPoP: await createDpopProof(keys, session.dpopPublicJwk, method, url.toString(), nonce, session.accessJwt),
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
