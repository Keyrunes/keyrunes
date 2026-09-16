# Feature specs

Three features are designed but **not yet built**. These documents are the
designs.

They are written using the Feynman method: the problem stated in plain words
before the mechanism, an analogy before the jargon, and the traps named out
loud. Each one is a **locked spec** — a contract for the implementation, not a
description of something that exists.

---

## What is here

| Feature | Spec | In one sentence | Status |
|---|---|---|---|
| Two-factor authentication | [2fa.md](./2fa.md) | A second lock on the door: the password, plus a code that changes every 30 seconds | Spec ready |
| WebAuthn / FIDO2 | [webauthn.md](./webauthn.md) | No password at all — the device itself proves who you are | Spec ready |
| OIDC / SSO provider | [oidc-sso.md](./oidc-sso.md) | KeyRunes becomes the "Sign in with…" button other applications use | Spec ready |

---

## Why this order

```
2FA ───────┐
           ├──► OIDC / SSO   (needs MFA inside the authorize flow)
WebAuthn ──┘
```

1. **2FA first.** It is the security foundation, and the smallest of the three.
2. **WebAuthn second.** It sits alongside 2FA rather than replacing it, and the
   v1 scope is passwordless login.
3. **OIDC/SSO last.** It consumes both: an authorization endpoint that cannot
   ask for a second factor is not worth building.

Going out of order means building the `authorize` flow twice.

---

## Rules that apply to all three

These are decided once here so that each spec does not re-argue them.

**Three surfaces, always.** Every feature ships UI *and* API *and* CLI. There is
no "API-only" feature in KeyRunes. Each spec has a coverage matrix in its §6
proving all three are covered.

**Every sensitive event is audited.** Enrollment, verification, failure, admin
reset, bypass — each writes an audit entry. If an operator later asks "who
turned this off and when", the answer must exist.

**Rate limiting and lockout.** Critical endpoints are throttled per IP and per
user. Ten failures within an hour locks the account temporarily. Without this,
a six-digit code is guessable in an afternoon.

**HTTPS in production**, with `localhost` exempt for development.

**Multi-tenant by default.** Every operation carries its organization's
`namespace` and is isolated through the PostgreSQL schema — see the
[architecture guide](../architecture.md#7-multi-tenancy-one-database-many-customers).

**The right cryptography for the job**, which is two different jobs:
- **Argon2** for anything that only ever needs checking, never reading back —
  codes, recovery secrets. One-way by design.
- **AES-GCM** for secrets that must be read back, such as the TOTP seed, which
  the server needs in order to compute the expected code.

**RS256 + JWKS, not HS256.** OIDC requires asymmetric signatures so that
relying parties can verify a token without holding a shared secret. KeyRunes
signs with HS256 today; migrating is cross-cutting work described in
[oidc-sso.md §11](./oidc-sso.md).

**`acr` and `amr` claims** are emitted in the `id_token` to say *how strongly*
the user authenticated. Defined in oidc-sso.md §5.2 and §7.

**Tests designed before code.** Each spec has a section listing cases per layer
(unit, integration, UI, CLI, end-to-end, migration) with a binary pass
criterion, and a matrix mapping every Definition-of-Done item to at least one
test. See the [testing guide](../testing.md) for the techniques.

---

## Audited counters

Every number below is checked against the §6 coverage matrix and the Definition
of Done in its own document. They are not estimates.

| Feature | API endpoints | Tera pages | CLI subcommands | Test scenarios |
|---|---|---|---|---|
| 2FA | 15 | 7 | 13 | 119 |
| WebAuthn | 11 | 5 | 9 | 117 |
| OIDC/SSO | 8 public + 12 admin/self | 10 | 14 | 186 |

---

## How to use these documents

Each spec ends with two sections that matter more than the rest:

- **Definition of Done** — an objective checklist. No interpretation required.
- **Suggested manual implementation order** — a sequence chosen to minimise
  cross-dependencies, so you are never blocked halfway through.

When you start a feature, open its document and work from that last section
upward. The earlier sections are reference for the questions that come up while
you do.
