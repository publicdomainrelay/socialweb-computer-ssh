// The co/core pairing client.
//
// Its own module rather than a few more lines in pds.js: that file's contract is
// that the only thing the page sends the server is the session it obtained, and
// a test asserts it. Pairing sends the session too, but for a different reason
// and to different endpoints, so it reads as its own client.
//
// It deposits no session and renews nothing. The server it is talking to holds
// the session already and is the only thing that refreshes it.

async function post(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
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
  return post('/cocore/status', session);
}

export function cocorePairStart(session) {
  return post('/cocore/pair/start', session);
}

// No session: the pairId is the whole request, and the server advances a pairing
// it already holds. Nothing about this call needs an access token.
export function cocorePairPoll(pairId) {
  return post('/cocore/pair/poll', { pairId });
}
