// Offline integration adapter for the ORIGINAL DUCTF 2025 Dockerfile apps.
//
// The embedded app.js is extracted from the real published Dockerfile, not
// independently rewritten. Only its fixed-port app.listen() is replaced with
// module.exports = app, so we can bind loopback and avoid collisions.
// This test never connects to a remote target or invokes a shell command.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createRequire } = require("node:module");

async function run() {
  const [dockerfile, query] = process.argv.slice(2);
  if (!dockerfile || query === undefined) {
    throw new Error("Usage: node phase16_node_case.js Dockerfile query");
  }
  const source = fs.readFileSync(dockerfile, "utf8");
  const match = source.match(/RUN cat <<EOF > app\.js\s*\n([\s\S]*?)\nEOF/);
  if (!match) throw new Error("Original Dockerfile app.js heredoc not found");
  const code = match[1];
  const listen = "app.listen(8000, () => console.log('App listening'));";
  if (!code.includes(listen)) throw new Error("Unexpected original listen directive");
  const appCode = code.replace(listen, "module.exports = app;");
  const localRequire = createRequire(path.join(path.dirname(path.resolve(dockerfile)), "package.json"));
  const moduleObject = { exports: {} };
  vm.runInNewContext(appCode, {
    require: localRequire,
    module: moduleObject,
    console,
  }, { timeout: 5000, filename: "original-ductf-app.js" });
  const app = moduleObject.exports;
  if (!app || typeof app.listen !== "function") {
    throw new Error("Original app did not export an Express handler");
  }
  const server = await new Promise((resolve, reject) => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    listener.on("error", reject);
  });
  try {
    const port = server.address().port;
    const reply = await fetch("http://127.0.0.1:" + port + "/?" + query, {
      method: "GET",
      signal: AbortSignal.timeout(6000),
    });
    const body = await reply.text();
    process.stdout.write(JSON.stringify({ status: reply.status, body }) + "\n");
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
}

run().catch(err => {
  process.stderr.write(String(err && err.stack || err) + "\n");
  process.exitCode = 1;
});
