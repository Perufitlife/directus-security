# directus-security

> Audit any **Directus** instance for the misconfigurations that actually leak data — public-role read exposure, user enumeration, unauthenticated version/schema leaks, GraphQL introspection, and the `search`-param field-enumeration oracle — and **prove each one live with an anonymous probe**. Other checklists tell you what *might* be wrong; this fetches the bytes and shows you what *is*.

> ⚡ **Run it in one line, no admin token, no install:**
> ```bash
> npx directus-security --url https://your-directus.example.com
> ```

> 🤝 **Want it done for you?** [Fixed-scope audit — $99 / 24h](https://buy.stripe.com/3cIeVdgikfj47yx9LkcAo0m): I verify each finding live and send a written report with the exact policy fixes.

[![npm](https://img.shields.io/npm/v/directus-security?color=red)](https://www.npmjs.com/package/directus-security) [![downloads](https://img.shields.io/npm/dw/directus-security)](https://www.npmjs.com/package/directus-security) ![license](https://img.shields.io/badge/license-MIT-green) ![node](https://img.shields.io/badge/node-%3E%3D18-blue) ![deps](https://img.shields.io/badge/dependencies-0-brightgreen)

```
$ npx directus-security --url https://directus.example.com
1 critical, 2 high, 1 medium — 4 CONFIRMED via anonymous probe
  CRITICAL  /items/posts            public-role read enabled — rows reachable anonymously
  HIGH      /items/posts?search=…   search-param field enumeration (CVE-2025-30352 class)
  HIGH      /items/directus_users   user list exposed (name + email)
  MEDIUM    /server/specs/oas       Directus version leaked unauthenticated (CVE-2025-53887 class)
```

## Why this exists

Directus powers headless backends at Tripadvisor, Adobe and Mercedes, and the
default access model makes one mistake very easy: leaving **read** enabled for
the **Public** policy. The result is an API anyone can read. 2025 brought a
cluster of unauthenticated CVEs that map *exactly* to anonymous probes:

- [CVE-2025-30352](https://github.com/directus/directus/security/advisories/GHSA-m5q3-8wgf-x8xf) — the `search` query parameter enumerates non-permitted fields, leaking emails and **password hashes** one character at a time.
- [CVE-2025-53887](https://nvd.nist.gov/vuln/detail/CVE-2025-30352) — the Directus version is exposed unauthenticated via `/server/specs/oas`, letting attackers match your build to known exploits.
- CVE-2025-64749 — collection-existence leak via error-message diffing.
- CVE-2025-53889 — unauthenticated Flow trigger.

`directus-security` checks for these and **confirms the real ones** by issuing the
exact anonymous request an attacker would — so you triage facts, not maybes.

## What it checks

| Check | Severity | How it's confirmed |
|---|---|---|
| Public-role read on a collection | critical | anonymous `GET /items/{collection}` returns rows |
| `search`-param field enumeration | high | anonymous `GET /items/{collection}?search=…` answers (CVE-2025-30352 class) |
| `/items/directus_users` user enumeration | high | anonymous read returns the user list (name + email) |
| Unauthenticated version/schema leak | medium | `/server/info` or `/server/specs/oas` returns the version unauth (CVE-2025-53887 class) |
| GraphQL introspection in prod | medium | `__schema` query answered on `/graphql` or `/graphql/system` |

## Usage

```bash
# Probe a live instance (guesses common collection names)
npx directus-security --url https://directus.example.com

# Probe specific collections
npx directus-security --url https://directus.example.com --collections posts,authors

# Learn your exact collection names from a Directus schema snapshot, then probe
npx directus-security --url https://directus.example.com --snapshot ./snapshot.json

# Write a shareable HTML report
npx directus-security --url https://directus.example.com --html report.html

# Static only (no requests sent)
npx directus-security --url https://directus.example.com --no-probe
```

Output is JSON on stdout (pipe it into CI) and a one-line summary on stderr.
Exit is non-zero only on usage errors — gate your pipeline on the JSON `summary`.

## Install (optional)

```bash
npm i -g directus-security
directus-security --url https://directus.example.com
```

Zero dependencies. Your data and credentials never leave your machine — every
request goes straight from the tool to your Directus instance.

## Sister tools

Same active-probe philosophy for the rest of the backend stack, all MIT:

[strapi-security](https://github.com/Perufitlife/strapi-security) ·
[supabase-security](https://github.com/Perufitlife/supabase-security-skill) ·
[pocketbase-security](https://github.com/Perufitlife/pocketbase-security-skill) ·
[firebase-security](https://github.com/Perufitlife/firebase-security-skill) ·
[appwrite-security](https://github.com/Perufitlife/appwrite-security-skill) ·
[nhost-security](https://github.com/Perufitlife/nhost-security-skill)

## License

MIT © [Renzo Madueno](https://github.com/Perufitlife)

---

📚 Part of [**Awesome Backend Security Auditors**](https://github.com/Perufitlife/awesome-backend-security) — the full collection of keyless active-probe auditors.
