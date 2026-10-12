import { assert, assertEquals, assertThrows } from "@std/assert";
import { buildUserData, listUserDataModules } from "@publicdomainrelay/cloud-init-common";
import { contractUserData } from "@publicdomainrelay/socialweb-computer-requester-inproc";

const ROOT = new URL("../", import.meta.url).pathname;
const SELF = new URL(import.meta.url).pathname;
const SCANNED = ["lib", "hono-socialweb-computer-ssh", "scripts", "test", "deno.json", ".github"];
const SCANNED_EXTENSIONS = [".ts", ".json", ".sh", ".yaml", ".yml"];
const FORBIDDEN: RegExp[] = [
  /websocat/i,
  /fedproxy-client/,
  /wootty/i,
  /JSR_URL/,
  /tunnel-subscriber/,
  /fedproxy-host|fedingressHost/,
  /user-data-transport/,
  /relay-fqdn/,
  /transport\s*:\s*["'`](?!iroh["'`])/,
];

async function scannedFiles(): Promise<string[]> {
  const files: string[] = [];
  const stack = SCANNED.map((top) => `${ROOT}${top}`);
  while (stack.length) {
    const path = stack.pop()!;
    const stat = await Deno.stat(path).catch(() => undefined);
    if (!stat) continue;
    if (stat.isFile) {
      files.push(path);
      continue;
    }
    for await (const entry of Deno.readDir(path)) {
      const child = `${path}/${entry.name}`;
      if (entry.isDirectory) stack.push(child);
      else if (SCANNED_EXTENSIONS.some((ext) => entry.name.endsWith(ext)) && child !== SELF) files.push(child);
    }
  }
  return files;
}

Deno.test("no transport other than iroh is requested", () => {
  const userData = contractUserData();
  assertEquals(userData.transport, "iroh");
  const composed = buildUserData({ ctx: { vmName: "g", sshAuthorizedKey: "ssh-ed25519 AAAA k" }, modules: [userData.transport] });
  assert(composed.includes("iroh.service"), "the composed guest runs the iroh listener");
  for (const legacy of ["tunnel", "fedproxy-ssh", "fedproxy-web", "wootty"]) {
    assert(!listUserDataModules().includes(legacy), `${legacy} is still offered to the gateway`);
    assertThrows(() => buildUserData({ modules: [legacy] }), Error, "iroh");
  }
});

Deno.test("no source, script or workflow in socialweb-computer-ssh names a legacy guest transport", async () => {
  const offenders: string[] = [];
  for (const path of await scannedFiles()) {
    const text = await Deno.readTextFile(path);
    for (const re of FORBIDDEN) if (re.test(text)) offenders.push(`${path.slice(ROOT.length)} ${re}`);
  }
  assertEquals(offenders, []);
});
