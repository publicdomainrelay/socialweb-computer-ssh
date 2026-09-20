/**
 * A secp256k1 private key persisted as a hex string in its own file, generated
 * on first use.
 *
 * The key outlives the process that made it: a DID derived from it is registered
 * once rather than per run, so anything else holding a reference -- a PLC entry,
 * a repo whose commits it signs -- stays valid across restarts. Losing the file
 * is not a restart, it is a new identity.
 *
 * Written 0600 inside a 0700 directory. The parent is created here rather than
 * left to the caller because a key that lands in a world-readable directory is
 * leaked before anything reads it back.
 */
export async function loadOrCreateKeyHex(path: string): Promise<string> {
  const existing = await Deno.readTextFile(path).then((s) => s.trim()).catch(() => "");
  if (existing) return existing;

  const { Secp256k1Keypair } = await import("@atproto/crypto");
  const kp = await Secp256k1Keypair.create({ exportable: true });
  const hex = Array.from(await kp.export()).map((b) => b.toString(16).padStart(2, "0")).join("");

  const dir = path.split("/").slice(0, -1).join("/");
  if (dir) await Deno.mkdir(dir, { recursive: true, mode: 0o700 });
  await Deno.writeTextFile(path, hex, { mode: 0o600 });

  return hex;
}
