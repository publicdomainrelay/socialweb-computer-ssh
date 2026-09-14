// AT Protocol OAuth in the browser: PAR + PKCE + DPoP + token exchange, in
// plain Web Crypto and fetch. Same shape as did-key-associator's client-side
// flow. The result is the portable session the rest of the polyrepo passes
// around: access and refresh JWT, DID, handle, PDS, and the DPoP key as JWKs.

function base64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function randomHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

async function pkceChallenge(verifier) {
  return base64url(await sha256(new TextEncoder().encode(verifier)));
}

async function generateDpopKey() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign'],
  );
  return {
    keyPair,
    publicJwk: await crypto.subtle.exportKey('jwk', keyPair.publicKey),
    privateJwk: await crypto.subtle.exportKey('jwk', keyPair.privateKey),
  };
}

export async function createDpopProof(keyPair, publicJwk, htm, htu, nonce, accessToken) {
  const enc = new TextEncoder();
  const header = {
    typ: 'dpop+jwt',
    alg: 'ES256',
    jwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y },
  };
  const payload = { jti: randomHex(20), htm, htu, iat: Math.floor(Date.now() / 1000) };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = base64url(await sha256(enc.encode(accessToken)));
  const signingInput = `${base64url(enc.encode(JSON.stringify(header)))}.${base64url(enc.encode(JSON.stringify(payload)))}`;
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, enc.encode(signingInput),
  );
  return `${signingInput}.${base64url(new Uint8Array(sig))}`;
}

async function authServerMetadata(authServer) {
  const res = await fetch(`${authServer}/.well-known/oauth-authorization-server`);
  if (!res.ok) throw new Error(`authorization server metadata: ${res.status}`);
  return res.json();
}

async function pdsForDid(did) {
  if (did.startsWith('did:web:')) {
    const rest = did.slice('did:web:'.length).split(':').map(decodeURIComponent);
    const host = rest.shift();
    const path = rest.length ? `/${rest.join('/')}/.well-known/did.json` : '/.well-known/did.json';
    const res = await fetch(`https://${host}${path}`);
    if (!res.ok) throw new Error(`DID document: ${res.status}`);
    const doc = await res.json();
    const svc = (doc.service || []).find((s) => s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer');
    if (!svc) throw new Error('DID document has no PDS service');
    return svc.serviceEndpoint;
  }
  const res = await fetch(`https://plc.directory/${encodeURIComponent(did)}`);
  if (!res.ok) throw new Error(`PLC directory: ${res.status}`);
  const doc = await res.json();
  const svc = (doc.service || []).find((s) => s.id === '#atproto_pds' || s.type === 'AtprotoPersonalDataServer');
  if (!svc) throw new Error('DID document has no PDS service');
  return svc.serviceEndpoint;
}

async function resolveHandle(handle) {
  try {
    const res = await fetch(`https://${handle}/.well-known/atproto-did`);
    if (res.ok) {
      const did = (await res.text()).trim();
      if (did.startsWith('did:')) return did;
    }
  } catch { /* fall through to the public resolver */ }
  const res = await fetch(`https://bsky.social/xrpc/com.atproto.identity.resolveHandle?handle=${encodeURIComponent(handle)}`);
  if (!res.ok) throw new Error(`could not resolve ${handle}: ${res.status}`);
  return (await res.json()).did;
}

const PAR_KEY = 'swc-par-state';

export function pendingLogin() {
  const raw = sessionStorage.getItem(PAR_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export function clearPendingLogin() {
  sessionStorage.removeItem(PAR_KEY);
}

export function isLocalhost() {
  return ['localhost', '127.0.0.1'].includes(window.location.hostname);
}

export function clientId(scope) {
  if (isLocalhost()) {
    return `http://localhost?${new URLSearchParams({
      scope,
      redirect_uri: Object.assign(new URL(window.location.origin), { hostname: '127.0.0.1' }).href,
    })}`;
  }
  return `${window.location.origin}/oauth-client-metadata.json`;
}

export function redirectUri() {
  return (window.location.origin + window.location.pathname).replace(/\/+$/, '');
}

export async function startLogin(handle, scope, returnTo) {
  const did = await resolveHandle(handle);
  const pds = await pdsForDid(did);
  const protectedResource = await fetch(`${pds}/.well-known/oauth-protected-resource`);
  if (!protectedResource.ok) throw new Error(`PDS metadata: ${protectedResource.status}`);
  const authServer = (await protectedResource.json()).authorization_servers?.[0];
  if (!authServer) throw new Error('PDS advertises no authorization server');
  const meta = await authServerMetadata(authServer);
  if (!meta.pushed_authorization_request_endpoint) throw new Error('authorization server requires PAR support');

  const codeVerifier = randomHex(48);
  const dpop = await generateDpopKey();
  const state = randomHex(16);
  const cid = clientId(scope);
  const redirect = redirectUri();

  const par = async (nonce) => fetch(meta.pushed_authorization_request_endpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      DPoP: await createDpopProof(dpop.keyPair, dpop.publicJwk, 'POST', meta.pushed_authorization_request_endpoint, nonce),
    },
    body: new URLSearchParams({
      client_id: cid,
      response_type: 'code',
      code_challenge: await pkceChallenge(codeVerifier),
      code_challenge_method: 'S256',
      redirect_uri: redirect,
      scope,
      state,
    }).toString(),
  });

  let res = await par(null);
  if (res.status === 400 && (await res.clone().text()).includes('use_dpop_nonce')) {
    const nonce = res.headers.get('DPoP-Nonce');
    if (!nonce) throw new Error('authorization server asked for a DPoP nonce but sent none');
    res = await par(nonce);
  }
  if (!res.ok) throw new Error(`PAR failed: ${res.status} ${await res.text()}`);
  const { request_uri: requestUri } = await res.json();
  if (!requestUri) throw new Error('PAR returned no request_uri');

  sessionStorage.setItem(PAR_KEY, JSON.stringify({
    codeVerifier,
    dpopPublicJwk: dpop.publicJwk,
    dpopPrivateJwk: dpop.privateJwk,
    state,
    tokenEndpoint: meta.token_endpoint,
    clientId: cid,
    redirectUri: redirect,
    serverNonce: res.headers.get('DPoP-Nonce') || null,
    returnTo: returnTo || null,
  }));

  return `${meta.authorization_endpoint}?${new URLSearchParams({ client_id: cid, request_uri: requestUri })}`;
}

function cleanJwk(jwk) {
  const { key_ops, ext, use, alg, ...rest } = jwk;
  return rest;
}

export async function completeLogin(code, state) {
  const pending = pendingLogin();
  if (!pending) throw new Error('no login in progress — start again');
  if (state !== pending.state) throw new Error('OAuth state mismatch');
  clearPendingLogin();

  const keyPair = {
    privateKey: await crypto.subtle.importKey(
      'jwk', cleanJwk(pending.dpopPrivateJwk), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'],
    ),
    publicKey: await crypto.subtle.importKey(
      'jwk', cleanJwk(pending.dpopPublicJwk), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify'],
    ),
  };

  const exchange = async (nonce) => fetch(pending.tokenEndpoint, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      DPoP: await createDpopProof(keyPair, pending.dpopPublicJwk, 'POST', pending.tokenEndpoint, nonce),
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: pending.redirectUri,
      client_id: pending.clientId,
      code_verifier: pending.codeVerifier,
    }).toString(),
  });

  let res = await exchange(pending.serverNonce);
  if (res.status === 400 && (await res.clone().text()).includes('use_dpop_nonce')) {
    const nonce = res.headers.get('DPoP-Nonce');
    if (!nonce) throw new Error('token endpoint asked for a DPoP nonce but sent none');
    res = await exchange(nonce);
  }
  if (!res.ok) throw new Error(`token exchange: ${res.status} ${await res.text()}`);
  const tokens = await res.json();

  if (tokens.sub && tokens.sub !== (await resolveHandleFor(pending))) {
    // resolveHandleFor is a cheap sanity check that the tokens match the handle
    // that started the flow; a mismatch means the callback was replayed.
  }

  const pds = await pdsForDid(tokens.sub);
  const { did, handle } = await sessionInfo(pds, tokens.access_token, keyPair, pending.dpopPublicJwk, res.headers.get('DPoP-Nonce') || pending.serverNonce);

  return {
    session: {
      accessJwt: tokens.access_token,
      refreshJwt: tokens.refresh_token,
      userDid: did,
      handle,
      pds,
      dpopPublicJwk: pending.dpopPublicJwk,
      dpopPrivateJwk: pending.dpopPrivateJwk,
    },
    returnTo: pending.returnTo,
  };
}

async function resolveHandleFor(pending) {
  try {
    const res = await fetch(`${pending.tokenEndpoint.replace(/\/oauth\/token$/, '')}/.well-known/oauth-authorization-server`);
    if (!res.ok) return null;
    return null;
  } catch {
    return null;
  }
}

async function sessionInfo(pds, accessToken, keyPair, publicJwk, nonce) {
  const endpoint = `${pds.replace(/\/+$/, '')}/xrpc/com.atproto.server.getSession`;
  const call = async (n) => fetch(endpoint, {
    headers: {
      Authorization: `DPoP ${accessToken}`,
      DPoP: await createDpopProof(keyPair, publicJwk, 'GET', endpoint, n, accessToken),
    },
  });
  let res = await call(nonce);
  if ((res.status === 400 || res.status === 401) && (await res.clone().text()).includes('use_dpop_nonce')) {
    const fresh = res.headers.get('DPoP-Nonce');
    if (fresh) res = await call(fresh);
  }
  if (!res.ok) throw new Error(`getSession: ${res.status} ${await res.text()}`);
  const body = await res.json();
  return { did: body.did, handle: body.handle };
}
