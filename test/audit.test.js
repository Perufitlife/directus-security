// Minimal test: simulate a Directus instance via fetch monkeypatch and assert
// the auditor confirms a public-read leak + user enumeration + version leak,
// and stays quiet on a locked instance.
import { audit } from "../scripts/audit.js";
import assert from "node:assert";

function mockFetch({ publicRead = false, users = false, version = false } = {}) {
  return async (url, opts = {}) => {
    const u = String(url);
    const wrap = (status, body, isText = false) => ({
      ok: status < 400, status, headers: { get: () => null },
      text: async () => (isText ? body : JSON.stringify(body)),
      json: async () => (isText ? JSON.parse(body) : body),
    });

    if (u.includes("/items/directus_users") || (u.includes("/users") && !u.includes("/items/"))) {
      return users ? wrap(200, { data: [{ id: 1, first_name: "Admin", email: "a@b.c" }] }) : wrap(403, { data: [] });
    }
    if (u.includes("/server/info")) {
      return version ? wrap(200, { data: { version: "11.2.0" } }) : wrap(401, {});
    }
    if (u.includes("/server/specs/oas")) return wrap(401, {});
    if (u.includes("/graphql")) return wrap(404, {});
    if (u.includes("/items/")) {
      return publicRead ? wrap(200, { data: [{ id: 1, title: "x", body: "y" }] }) : wrap(403, { errors: [] });
    }
    return wrap(404, {});
  };
}

let pass = 0;

globalThis.fetch = mockFetch({ publicRead: true, users: true, version: true });
let r = await audit({ url: "https://demo.test", collections: ["posts"] });
assert.ok(r.findings.find((f) => f.check === "public_read"), "should flag public read");
assert.ok(r.findings.find((f) => f.check === "search_field_enum"), "should flag search field enum on public collection");
assert.ok(r.findings.find((f) => f.check === "user_enumeration"), "should flag user enumeration");
assert.ok(r.findings.find((f) => f.check === "version_leak"), "should flag version leak");
assert.ok(r.active_probe.confirmed >= 4, "should confirm >=4 leaks");
console.log("PASS: leaky instance flagged (public read + search enum + user enum + version leak)"); pass++;

globalThis.fetch = mockFetch({ publicRead: false, users: false, version: false });
r = await audit({ url: "https://locked.test", collections: ["posts"] });
assert.strictEqual(r.findings.length, 0, "locked instance should be clean");
console.log("PASS: locked instance is clean"); pass++;

console.log(`\n${pass}/2 tests passed`);
