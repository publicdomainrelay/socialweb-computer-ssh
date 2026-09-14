import type { SessionVerifier, VerifiedSession } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

export interface SessionVerifierOptions {
  timeoutMs?: number;
}

const LOOPBACK = ["127.0.0.1", "[::1]", "::1", "localhost"];

// The browser signs in and writes its own key records; the only thing the
// server does with a session is hand it to the requester process. That still
// means an unauthenticated endpoint accepts a session blob, so the blob is
// proved against the PDS before it is stored: a live DPoP-bound getSession that
// has to name the same DID the blob claims.
function usablePds(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol === "https:") return url.origin;
  if (url.protocol === "http:" && LOOPBACK.includes(url.hostname)) return url.origin;
  return null;
}

export function createAtprotoSessionVerifier(opts: SessionVerifierOptions = {}): SessionVerifier {
  const timeoutMs = opts.timeoutMs ?? 15_000;

  return {
    async verify(session: OAuthSessionData): Promise<VerifiedSession | null> {
      if (typeof session?.userDid !== "string" || !session.userDid.startsWith("did:")) return null;
      if (typeof session.accessJwt !== "string" || !session.accessJwt) return null;
      if (typeof session.dpopPrivateJwk !== "object" || session.dpopPrivateJwk === null) return null;
      const pds = usablePds(String(session.pds ?? ""));
      if (!pds) return null;

      let key: CryptoKey;
      try {
        const { key_ops, ext, use, alg, ...jwk } = session.dpopPrivateJwk as Record<string, unknown>;
        key = await crypto.subtle.importKey(
          "jwk",
          jwk as JsonWebKey,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["sign"],
        );
      } catch {
        return null;
      }

      const endpoint = `${pds}/xrpc/com.atproto.server.getSession`;
      const call = async (nonce?: string | null): Promise<Response> => {
        const header = {
          typ: "dpop+jwt",
          alg: "ES256",
          jwk: {
            kty: session.dpopPublicJwk?.kty ?? "EC",
            crv: session.dpopPublicJwk?.crv ?? "P-256",
            x: session.dpopPublicJwk?.x ?? "",
            y: session.dpopPublicJwk?.y ?? "",
          },
        };
        const payload: Record<string, unknown> = {
          jti: crypto.randomUUID().replace(/-/g, ""),
          htm: "GET",
          htu: endpoint,
          iat: Math.floor(Date.now() / 1000),
        };
        if (nonce) payload.nonce = nonce;
        const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
        const signature = await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          key,
          new TextEncoder().encode(signingInput),
        );
        return await fetch(endpoint, {
          headers: {
            Authorization: `DPoP ${session.accessJwt}`,
            DPoP: `${signingInput}.${b64urlBytes(new Uint8Array(signature))}`,
          },
          signal: AbortSignal.timeout(timeoutMs),
        });
      };

      try {
        let res = await call(session.dpopNonce ?? null);
        if ((res.status === 400 || res.status === 401) && (await res.clone().text()).includes("use_dpop_nonce")) {
          const fresh = res.headers.get("DPoP-Nonce");
          if (fresh) res = await call(fresh);
        }
        if (!res.ok) return null;
        const body = await res.json() as { did?: string; handle?: string };
        if (body.did !== session.userDid) return null;
        return { did: body.did, handle: body.handle ?? body.did };
      } catch {
        return null;
      }
    },
  };
}

function b64url(text: string): string {
  return b64urlBytes(new TextEncoder().encode(text));
}

function b64urlBytes(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
