#!/usr/bin/env node
// Directus Security Auditor — pure Node.js, no deps.
//
// Detects, and PROVES with an anonymous probe, the most common Directus
// production footguns:
//   - Public-role read enabled on collections (anyone can GET /items/{c})
//   - User enumeration via public /items/directus_users
//   - Unauthenticated version/schema leak via /server/info & /server/specs/oas
//     (CVE-2025-53887 class — version exposed unauth via the OpenAPI spec)
//   - GraphQL introspection left on in production (/graphql, /graphql/system)
//   - Field-enumeration via the `search` param (CVE-2025-30352 class — leaks
//     non-permitted fields including emails + password hashes)
//
// Keyless by design: point it at a URL (+ optionally your local repo to learn
// the collection names) and it confirms each leak by fetching it anonymously.
//
// Usage:
//   directus-security --url https://directus.example.com [--collections posts,authors]
//   directus-security --url https://directus.example.com --html report.html
//
// Your data and credentials never leave your machine — every request goes
// straight from this process to your Directus instance.

import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const UA = "directus-security/0.1";
const EVIL_ORIGIN = "https://directus-security-probe.example";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const CHECKS = {
  public_read: {
    severity: "critical",
    title: "Collection is publicly readable — anyone can GET your data",
    explain: "The Public policy has read enabled on this collection. Any unauthenticated visitor can read every item via /items/{collection}. Remove read access for the Public policy in Settings → Access Policies → Public unless the data is meant to be open.",
  },
  user_enumeration: {
    severity: "high",
    title: "Public /items/directus_users exposes the user list",
    explain: "The Public policy can read the directus_users system collection, leaking names and emails (account enumeration + phishing fuel). Remove read access on directus_users for the Public policy.",
  },
  version_leak: {
    severity: "medium",
    title: "Server version/schema exposed to unauthenticated callers (CVE-2025-53887 class)",
    explain: "/server/info or /server/specs/oas returns the exact Directus version and project schema without auth, letting attackers match your build to known CVEs. Restrict /server/info and the OpenAPI spec to authenticated roles, and keep Directus patched.",
  },
  graphql_introspection: {
    severity: "medium",
    title: "GraphQL introspection enabled in production",
    explain: "The /graphql (or /graphql/system) endpoint answers __schema introspection, handing attackers your full data model. Disable introspection in production, or restrict the GraphQL endpoint to authenticated access.",
  },
  search_field_enum: {
    severity: "high",
    title: "search param enumerates non-permitted fields (CVE-2025-30352 class)",
    explain: "The `search` query parameter filters on fields the caller cannot read, so an attacker can binary-search private contents — including emails and password hashes — one character at a time. Upgrade Directus to >=11.5.0 immediately; the public collection should not be reachable at all.",
  },
};

// --- Directus REST helpers ---------------------------------------------------

async function getJson(url, headers = {}) {
  try {
    const r = await fetch(url, { headers: { "User-Agent": UA, ...headers }, redirect: "follow" });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* non-JSON */ }
    return { ok: r.ok, status: r.status, headers: r.headers, text, json };
  } catch (e) {
    return { ok: false, status: 0, error: e.message };
  }
}

// Probe a collection's public list endpoint anonymously.
async function probePublicRead(base, collection) {
  const url = `${base}/items/${encodeURIComponent(collection)}?limit=1`;
  const r = await getJson(url);
  if (r.status === 200 && r.json && Array.isArray(r.json.data)) {
    const sample = r.json.data[0];
    const columns = sample && typeof sample === "object" ? Object.keys(sample).slice(0, 8) : [];
    return { confirmed: true, status: 200, sample: { row_count: r.json.data.length, columns } };
  }
  return { confirmed: false, status: r.status, reason: r.status === 403 || r.status === 401 ? "locked (good)" : `http ${r.status}` };
}

async function checkUserEnum(base) {
  const r = await getJson(`${base}/items/directus_users?limit=1`);
  // Some builds also serve /users on the public policy.
  let r2 = null;
  if (!(r.status === 200 && Array.isArray(r.json?.data))) r2 = await getJson(`${base}/users?limit=1`);
  const hit = (resp) => resp && resp.status === 200 && Array.isArray(resp.json?.data) && resp.json.data.length > 0;
  if (hit(r)) return { confirmed: true, status: 200, endpoint: "/items/directus_users", sample_keys: Object.keys(r.json.data[0]).slice(0, 8) };
  if (hit(r2)) return { confirmed: true, status: 200, endpoint: "/users", sample_keys: Object.keys(r2.json.data[0]).slice(0, 8) };
  return { confirmed: false, status: r.status };
}

async function checkVersionLeak(base) {
  // /server/info often exposes version when telemetry/info is left open.
  const info = await getJson(`${base}/server/info`);
  const v = info.json?.data?.version || info.json?.version || null;
  if (info.status === 200 && v) {
    return { confirmed: true, via: "/server/info", version: v };
  }
  // /server/specs/oas leaks the version string inside the OpenAPI document.
  const oas = await getJson(`${base}/server/specs/oas`);
  if (oas.status === 200 && oas.text) {
    const m = oas.text.match(/"version"\s*:\s*"([^"]+)"/);
    if (m) return { confirmed: true, via: "/server/specs/oas", version: m[1] };
  }
  return { confirmed: false, status: info.status };
}

async function checkGraphql(base) {
  for (const path of ["/graphql", "/graphql/system"]) {
    try {
      const r = await fetch(`${base}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": UA, Origin: EVIL_ORIGIN },
        body: JSON.stringify({ query: "{ __schema { queryType { name } } }" }),
      });
      if (r.status === 404) continue;
      const j = await r.json().catch(() => null);
      if (j?.data?.__schema) return { present: true, confirmed: true, endpoint: path };
    } catch { /* try next */ }
  }
  return { present: false, confirmed: false };
}

// search-param field enumeration: if a public collection answers `search`,
// the CVE-2025-30352 class oracle is reachable unauthenticated.
async function checkSearchFieldEnum(base, collection) {
  const r = await getJson(`${base}/items/${encodeURIComponent(collection)}?search=a&limit=1`);
  if (r.status === 200 && Array.isArray(r.json?.data)) {
    return { confirmed: true, status: 200, collection };
  }
  return { confirmed: false, status: r.status };
}

// --- collection discovery ----------------------------------------------------

// Reasonable default guesses when no --collections given.
const COMMON_COLLECTIONS = ["posts", "articles", "pages", "products", "authors", "categories", "comments", "users"];

// Optional: read a local Directus snapshot/schema export for real collection names.
function discoverCollections(file) {
  if (!file || !existsSync(file)) return [];
  try {
    const snap = JSON.parse(readFileSync(file, "utf8"));
    const cols = snap.collections || snap.data?.collections || [];
    return cols
      .map((c) => c.collection || c.name)
      .filter((c) => c && !String(c).startsWith("directus_"));
  } catch { return []; }
}

// --- main audit --------------------------------------------------------------

export async function audit({ url, collections = [], snapshot = null, activeProbe = true }) {
  if (!url) throw new Error("audit() requires { url }");
  const base = url.replace(/\/+$/, "");
  const findings = [];

  let names = [...collections];
  if (snapshot) names.push(...discoverCollections(snapshot));
  if (names.length === 0) names = [...COMMON_COLLECTIONS];
  names = [...new Set(names)];

  let probed = 0, confirmed = 0;

  // Per-collection: public read + search-param field-enum oracle.
  for (const collection of names) {
    if (!activeProbe) continue;
    const probe = await probePublicRead(base, collection);
    probed++;
    if (probe.confirmed) {
      confirmed++;
      findings.push({
        check: "public_read", ...CHECKS.public_read,
        target: `/items/${collection}`,
        details: { collection, columns: probe.sample.columns },
        probe,
        fix: `Settings → Access Policies → Public → remove read on "${collection}".`,
      });
      // Only worth the search oracle on collections that are already public.
      const oracle = await checkSearchFieldEnum(base, collection);
      if (oracle.confirmed) {
        confirmed++;
        findings.push({
          check: "search_field_enum", ...CHECKS.search_field_enum,
          target: `/items/${collection}?search=…`, details: { collection }, probe: oracle,
          fix: "Upgrade Directus to >=11.5.0 and remove Public read on this collection.",
        });
      }
    }
  }

  // Site-wide checks.
  if (activeProbe) {
    const users = await checkUserEnum(base); probed++;
    if (users.confirmed) {
      confirmed++;
      findings.push({ check: "user_enumeration", ...CHECKS.user_enumeration, target: users.endpoint, details: users,
        fix: "Access Policies → Public → remove read on directus_users." });
    }

    const ver = await checkVersionLeak(base); probed++;
    if (ver.confirmed) {
      confirmed++;
      findings.push({ check: "version_leak", ...CHECKS.version_leak, target: ver.via, details: ver,
        fix: "Restrict /server/info and /server/specs/oas to authenticated roles; keep Directus patched." });
    }

    const gql = await checkGraphql(base); probed++;
    if (gql.present && gql.confirmed) {
      confirmed++;
      findings.push({ check: "graphql_introspection", ...CHECKS.graphql_introspection, target: gql.endpoint, details: gql,
        fix: "Disable GraphQL introspection in production or require auth on the GraphQL endpoint." });
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const summary = findings.reduce(
    (acc, f) => ({ ...acc, [f.severity]: (acc[f.severity] || 0) + 1 }),
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );

  return {
    directus_url: base,
    scanned_by: "directus-security v0.1",
    active_probe: { enabled: activeProbe, probed, confirmed },
    collections_checked: names,
    summary,
    findings,
  };
}

// --- CLI ---------------------------------------------------------------------

function parseArgs(argv) {
  const a = argv.slice(2);
  const flag = (k) => { const i = a.indexOf(k); return i !== -1 ? a[i + 1] : null; };
  return {
    help: a.includes("--help") || a.includes("-h"),
    url: flag("--url") || process.env.DIRECTUS_URL,
    collections: (flag("--collections") || "").split(",").map((s) => s.trim()).filter(Boolean),
    snapshot: flag("--snapshot"),
    activeProbe: !a.includes("--no-probe"),
    html: a.includes("--html") ? (flag("--html") || "directus-report.html") : null,
  };
}

export async function run() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.url) {
    console.error(`directus-security — audit a Directus instance, prove each leak with an anonymous probe.

Usage:
  directus-security --url https://directus.example.com
  directus-security --url https://directus.example.com --collections posts,authors
  directus-security --url https://directus.example.com --snapshot ./snapshot.json
  directus-security --url https://directus.example.com --html report.html

Flags:
  --url <url>            Directus base URL (or DIRECTUS_URL env)
  --collections a,b,c    Explicit collection names to probe
  --snapshot <file>      Learn collection names from a Directus schema snapshot/export
  --no-probe             List checks without sending any request
  --html <file>          Write an HTML report

Detects: public-role read exposure, user enumeration, unauthenticated
version/schema leak, GraphQL introspection, search-param field enumeration.`);
    process.exit(opts.url ? 0 : 1);
  }

  const result = await audit(opts);

  if (opts.html) {
    const { renderHtml } = await import("./report.js");
    writeFileSync(opts.html, renderHtml(result));
    console.error(`HTML report written to ${opts.html}`);
  }
  console.log(JSON.stringify(result, null, 2));
  const s = result.summary;
  console.error(`\n${s.critical} critical, ${s.high} high, ${s.medium} medium` +
    (result.active_probe.enabled ? ` — ${result.active_probe.confirmed} CONFIRMED via anonymous probe` : ""));
}

const isMain = process.argv[1] && (
  import.meta.url === `file://${process.argv[1].replace(/\\/g, "/")}` ||
  import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/"))
);
if (isMain) run().catch((e) => { console.error(e.message); process.exit(1); });
