// The co/core pairing client.
//
// Its own module rather than a few more lines in pds.js: that file's contract is
// that the only thing the page sends the server is the session it obtained, and
// a test asserts it. Pairing sends the session too, but for a different reason
// and to different endpoints, so it reads as its own client.
//
// It borrows pds.js's refresh, though, and must: these requests carry the same
// session to the same server, and the server proves a deposit with a live call
// to the account's PDS. A page whose repo calls renew their token but whose
// pairing calls do not would work right up until the token aged out and then
// report the session as expired.

import { withRefresh } from './pds.js';

async function post(path, body, session) {
  const send = () => fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const res = session ? await withRefresh(session, send) : await send();

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const err = new Error((data && data.error) || `HTTP ${res.status}`);
    // Carried so the caller can tell "this session is no longer usable" from
    // "the service is unreachable": the first needs a sign-in, the second a retry.
    err.status = res.status;
    throw err;
  }
  return data;
}

export function cocoreStatus(session) {
  return post('/cocore/status', session, session);
}

export function cocorePairStart(session) {
  return post('/cocore/pair/start', session, session);
}

// No session: the pairId is the whole request, and the server advances a pairing
// it already holds. Nothing about this call needs an access token.
export function cocorePairPoll(pairId) {
  return post('/cocore/pair/poll', { pairId });
}
