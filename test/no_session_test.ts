import { assert, assertEquals } from "@std/assert";
import { explainNoSession } from "@publicdomainrelay/socialweb-computer-requester-inproc";

const CTX = { policy: "tangled-vouch", bidWindowSec: 30, vmReadyTimeoutSec: 300 };

Deno.test("a run with no bids explains itself instead of reporting success", () => {
  const msg = explainNoSession({ event: "no_bids", error: "no bids received within 30s" }, CTX);
  assert(msg.includes("No bids arrived within 30s"));
  assert(msg.includes("nothing ran"));
  // The knobs that actually change the outcome have to be named, or the message
  // is only a diagnosis the client cannot act on.
  assert(msg.includes("LC_POLICY_BID_WINDOW_SEC"));
  assert(msg.includes("LC_POLICY"));
  assert(msg.includes("tangled-vouch"));
});

Deno.test("a policy rejection names the policy and carries the violations", () => {
  const msg = explainNoSession(
    { event: "policy_rejected", error: "winner rejected by policy: not vouched" },
    CTX,
  );
  assert(msg.includes("policy rejected it"));
  assert(msg.includes("not vouched"));
  assert(msg.includes("LC_POLICY_ARGS"));
});

Deno.test("a VM that never answered is told apart from a VM never won", () => {
  const msg = explainNoSession({ event: "compute_request_complete", sshReady: false }, CTX);
  assert(msg.includes("did not come up within 300 seconds"));
});

Deno.test("an unrecognised stop still says something and never claims success", () => {
  const msg = explainNoSession({ event: "something_new" }, CTX);
  assert(msg.includes("did not complete"));
  assert(msg.includes("something_new"));
  assertEquals(msg.endsWith("\n"), true);
});
