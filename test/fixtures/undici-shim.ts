// Deno does not emulate `process.versions.undici`, and @atproto-labs/fetch-node's
// unicast guard reads exactly that to decide whether the runtime has undici's
// SSRF fix. Undefined fails the check, so `createDefaultFetch` throws
// "Unicast SSRF protection requires Node.js 20.6+" and anything constructing an
// IdResolver dies -- on Linux CI, where that package version takes the Node
// dispatcher path. The guard is asking whether undici is patched; Deno's fetch
// is not undici at all, so the question is inapplicable rather than unmet.
//
// Preloaded, not imported by application code: it is an environment quirk, and
// nothing in the service should depend on it.
const versions = process.versions as Record<string, string>;
if (!versions.undici) versions.undici = "6.11.1";
