# How KeyRunes is built

> A guided tour of the codebase for a human being. No prior knowledge of the
> project assumed. If a sentence here needs you to already know the answer,
> it is a bad sentence and should be rewritten.

---

## 0. How to read this document

It is written the way you would learn a city: first the shape of the place,
then one walk end to end, then street by street.

1. [What KeyRunes actually does](#1-what-keyrunes-actually-does)
2. [The one idea everything hangs off](#2-the-one-idea-everything-hangs-off)
3. [One request, all the way down](#3-one-request-all-the-way-down)
4. [The four layers and the rule between them](#4-the-four-layers-and-the-rule-between-them)
5. [The map: every directory](#5-the-map-every-directory)
6. [The data model](#6-the-data-model)
7. [Multi-tenancy: one database, many customers](#7-multi-tenancy-one-database-many-customers)
8. [RBAC, ABAC, ReBAC, PBAC without the acronyms](#8-rbac-abac-rebac-pbac-without-the-acronyms)
9. [Every dependency and why it is here](#9-every-dependency-and-why-it-is-here)
10. [Where do I put my new code?](#10-where-do-i-put-my-new-code)

---

## 1. What KeyRunes actually does

Imagine a large office building. At the front desk somebody checks your ID and
gives you a badge. Later, at the door of the server room, a reader checks
whether *that badge* opens *that door*.

KeyRunes is both of those things for a software system:

- **The front desk.** It stores users and passwords, checks them, and hands
  out a badge — here a JWT, a signed string the user carries around.
- **The door readers.** It answers the question "may user 42 do `delete` on
  `invoice:7`?" and replies allow or deny.

The point of running it as a separate service is that the office has many
doors, and you do not want every door to grow its own opinion about who is
allowed in. One place decides; everything else asks.

A second job follows from that: because one KeyRunes can serve several
unrelated customers at once ("tenants"), it also has to guarantee that
customer A can never see, touch, or even guess at customer B's users. That is
[section 7](#7-multi-tenancy-one-database-many-customers), and it shapes more
of the code than you would expect.

---

## 2. The one idea everything hangs off

Two words that look alike and mean completely different things:

| | Question | Analogy | In this code |
|---|---|---|---|
| **Authentication** | *Who are you?* | Showing your ID at the front desk | `user_service.rs`, `jwt_service.rs` |
| **Authorization** | *What may you do?* | The badge reader on a door | `policy_service.rs`, `group_service.rs` |

Almost every confusing bug in an access-control system comes from blurring
these. "The user is logged in" tells you nothing about whether they may delete
an invoice. KeyRunes keeps them in separate services, and the separation is
worth defending when you add code.

A third word joins them once there is more than one customer:

- **Tenancy** — *whose world are you in?* Every question above is really
  "who are you **in namespace `acme`**?". A user id is only meaningful
  alongside its namespace.

---

## 3. One request, all the way down

The fastest way to understand a codebase is to follow a single request. Let us
post a login.

```
POST /api/login   { "identity": "ana", "password": "hunter2", "namespace": "public" }
```

### Step 1 — the door: `src/main.rs`

`main.rs` is the wiring diagram. It has no business logic at all; it builds
things and bolts them together. In order it:

1. loads `.env`, sets up logging (`handler::logging::init_logging`),
2. opens the PostgreSQL pool and **runs the migrations on boot**
   (`sqlx::migrate!("./migrations")`),
3. constructs one repository per table-family, wraps each in an `Arc`,
4. constructs the services, handing them their repositories,
5. builds five routers and merges them,
6. attaches every service as an axum `Extension` so handlers can ask for them.

The five routers are the security perimeter, and they are worth memorising:

| Router | Who gets in | Guard |
|---|---|---|
| `public_router` | anyone | none |
| `protected_web_router` | any logged-in user | `require_auth` |
| `protected_api_router` | any logged-in user | `require_auth` |
| `admin_web_router` / `admin_router` | superadmins | `require_auth` + `require_superadmin` |
| `external_api_router` | other *machines* | `require_org_key_or_superadmin` |

`/api/login` lives in `public_router` — it must, since you cannot require a
token from someone who is asking for one.

> **Read this twice.** Whether a route is protected is decided *only* by which
> router you attach it to. Adding a route to the wrong `Router::new()` block
> silently publishes it to the internet. There is no second check further down.

### Step 2 — the middleware chain: `src/handler/`

Everything passes through `request_logging_middleware`. Protected routes then
pass through `require_auth`, which:

1. pulls the token out of the `Authorization: Bearer …` header **or** the
   session cookie (`extract_bearer_token`),
2. verifies it with `JwtService`,
3. inserts an `AuthenticatedUser` into the request extensions.

A handler that wants the caller writes `Extension(user): Extension<AuthenticatedUser>`
in its signature. If the middleware did not run, that extension is missing and
the handler will not be reachable — which is why the router table above is the
real perimeter.

Login skips all of this. It has no token yet.

### Step 3 — the entry point: `src/api/auth.rs`

`api::auth::login_api` is thin *on purpose*. Its whole job is translation:

- deserialize JSON into a request struct,
- call the service,
- turn the result into a status code and a JSON body.

There is no password comparison here, no SQL, no decision. If you ever find
yourself writing an `if` about *business* rules in `src/api/`, it belongs one
layer down.

The mirror image lives in `src/views/auth.rs`: same operation, but it renders
an HTML page with Tera instead of returning JSON, and sets a cookie instead of
returning a bare token. Two front doors, one engine.

### Step 4 — the decision: `src/services/user_service.rs`

This is where the thinking happens.

1. Look the user up by email or username, **within the namespace**.
2. Verify the password against the stored Argon2 hash.
3. Load the groups the user belongs to.
4. Ask `JwtService` to mint a token carrying the user id, the namespace and
   those groups.

Services never touch SQL. They talk to *traits* — `UserRepository`,
`GroupRepository` — and the trait is what makes the whole test suite possible
(see [the testing guide](./testing.md)).

### Step 5 — the storage: `src/repository/sqlx_impl.rs`

`PgUserRepository` implements `UserRepository` against real PostgreSQL. Every
single method starts the same way:

```rust
let mut tx = self.pool.begin().await?;
sqlx::query(&format!("SET LOCAL search_path TO \"{}\"", namespace))
    .execute(&mut *tx).await?;
```

That is the entirety of the multi-tenancy mechanism, and
[section 7](#7-multi-tenancy-one-database-many-customers) explains why it is
both elegant and slightly dangerous.

### Step 6 — the way back out

The `User` travels back up: repository → service → `api::auth` → JSON. If
anything failed, the error surfaces through `handler::errors`, which decides
whether the caller gets JSON or an HTML page based on the path and the
`Accept` header.

That is the whole journey. Every other request in the system is a variation on
it.

---

## 4. The four layers and the rule between them

```
            ┌─────────────────────────────────────────────┐
  HTTP  ──► │  src/api/      JSON in, JSON out            │  "translation"
            │  src/views/    forms in, HTML out           │
            ├─────────────────────────────────────────────┤
            │  src/handler/  middleware: auth, logs, 404s │  "the perimeter"
            ├─────────────────────────────────────────────┤
            │  src/services/ the rules. no SQL, no HTTP   │  "the thinking"
            ├─────────────────────────────────────────────┤
            │  src/repository/  traits + PostgreSQL impl  │  "the storage"
            └─────────────────────────────────────────────┘
                              │
                        PostgreSQL
```

**The rule: dependencies point downward, and nothing skips a layer upward.**

- `api/` and `views/` may call `services/`. They may not call `repository/`.
- `services/` may call `repository/` *traits*. They may not know about HTTP,
  status codes, Tera, or cookies.
- `repository/` knows SQL and nothing else. It never decides anything.

Why bother? Two concrete payoffs, not abstract purity:

1. **You can test the rules without a database.** A service takes a trait, so a
   test hands it a `MockUserRepository` that stores users in a `Vec`. That is
   why most of `tests/` runs in milliseconds with no Postgres.
2. **One rule, two front doors.** The HTML form at `/register` and the JSON
   endpoint at `/api/register` both call `UserService::register`. When we
   closed the privilege-escalation hole there, both were fixed by one change,
   because there was only one place where the rule lived.

`src/domain/` sits slightly outside the stack: it holds types that are correct
*by construction* (`Email`, `Password`) and are used by every layer.

---

## 5. The map: every directory

### `src/` — the application

| Path | What lives here | Responsibility |
|---|---|---|
| `main.rs` | boot + routing table | Build everything, wire it, serve. **No logic.** |
| `lib.rs` | module declarations | Exists so `tests/` can `use keyrunes::…`. Ten lines. |
| `constants.rs` | shared literals | Default namespace, the group names, and `is_privileged_group` — the denylist that stops an anonymous registration asking for `superadmin`. |

#### `src/api/` — the JSON surface

| File | Responsibility |
|---|---|
| `auth.rs` | register, login, refresh, `/api/me`, forgot/reset password |
| `admin.rs` | the superadmin console API: users, groups, policies, assignments (the largest file here, ~670 lines) |
| `organization.rs` | create/delete tenants, read and rotate the organization key |
| `user.rs` | self-service: update profile, change password |
| `external.rs` | `POST /api/check-permission` — the endpoint *other services* call |
| `health.rs` | `/api/health`, `/ready`, `/live`, plus self-probes of JWT and hashing |
| `deserializers.rs` | small serde helpers for lenient input shapes |
| `openapi.rs` | the `utoipa` document that feeds Swagger UI at `/swagger-ui` |

#### `src/views/` — the HTML surface

| File | Responsibility |
|---|---|
| `auth.rs` | login, register, dashboard, profile, change/forgot/reset password pages |
| `admin.rs` | the `/admin` page, plus `may_view_admin()` — the gate, extracted so it can be tested without a database |

#### `src/handler/` — middleware

| File | Responsibility |
|---|---|
| `auth.rs` | `require_auth`, `require_superadmin`, `require_groups`, `require_org_key_or_superadmin`, and `extract_bearer_token` (header **or** cookie) |
| `errors.rs` | `handler_404` and friends; decides JSON vs HTML from path + `Accept` |
| `logging.rs` | `init_logging` and the per-request logging middleware |

#### `src/services/` — the rules

| File | Responsibility |
|---|---|
| `user_service.rs` | registration, login, password reset, profile, first-user bootstrap. The biggest brain in the project (~1330 lines). Also holds `SettingsService`. |
| `jwt_service.rs` | mint, verify and refresh tokens. **The security boundary**: every protected route funnels through `verify_token`. |
| `policy_service.rs` | evaluate allow/deny for (user, resource, action); assign and revoke policies |
| `group_service.rs` | create and list groups, membership |
| `organization_service.rs` | create tenants, validate namespaces, rotate org keys |
| `email_service.rs` | send mail over SMTP with `lettre`, rendering Tera templates. Optional — if SMTP is unconfigured the server boots anyway and just logs it. |

#### `src/repository/` — storage

| File | Responsibility |
|---|---|
| `mod.rs` | the row structs (`User`, `Group`, `Policy`, `PolicyEffect`, …) and the **traits**: `UserRepository`, `GroupRepository`, `PolicyRepository`, `PasswordResetRepository`, `OrganizationRepository`, `SettingsRepository` |
| `sqlx_impl.rs` | one `Pg…Repository` per trait, all doing `SET LOCAL search_path` first |

#### `src/domain/` — types that cannot be wrong

| File | Responsibility |
|---|---|
| `user.rs` | `Email` (validated by regex on construction) and `Password` (wraps `SecretString`, enforces a minimum length, never prints itself) |
| `organization.rs` | `Organization` and `NewOrganization` |

The trick worth stealing: `Email::try_from` is the *only* way to build an
`Email`. Once a function takes an `Email` rather than a `String`, it no longer
needs to check anything — the type already did.

#### `src/bin/` — command-line tools

| File | Responsibility |
|---|---|
| `cli.rs` | the admin CLI (`clap`): bootstrap the first superadmin, create groups, list things. ~1330 lines. |
| `verify_schema.rs` | check a tenant schema matches what the code expects |
| `cleanup_migrations.rs` | maintenance helper for the migration table |

### Outside `src/`

| Path | What it is |
|---|---|
| `migrations/` | sqlx migrations for the **public** schema, applied automatically on boot |
| `migrations/tenant/001_init_tenant.sql` | the template applied inside each new tenant schema |
| `templates/` | Tera HTML: pages, `errors/*.html`, and `mail/password_reset.html` |
| `tests/` | integration tests — see [the testing guide](./testing.md) |
| `hurl/` | end-to-end HTTP tests written in [Hurl](https://hurl.dev), run against a live server |
| `docs/` | you are here |
| `.cargo/mutants.toml` | mutation-testing configuration (**not** the repo root — cargo-mutants reads it from `.cargo/`) |
| `.sqlx/` | cached query metadata so `cargo build` works offline (`SQLX_OFFLINE=true`) |
| `Makefile` | the task list. `make help` prints everything. |

---

## 6. The data model

Seven tables carry the whole system.

```
organizations ──┐  (a tenant: name, namespace, secret_key)
                │
                ▼
              users ───────┬──────────► user_groups ──────► groups
       (email, username,   │                                  │
        argon2 hash,       │                                  │
        first_login)       │                                  ▼
                           └──────────► user_policies ──► policies ◄── group_policies
                                                        (resource,
                                                         action,
                                                         effect,
                                                         conditions)

              password_reset_tokens        settings
```

Two things to notice, because they explain a lot of otherwise odd code:

**Every row has two ids.** `user_id` is a `BIGINT` used for joins and foreign
keys; `external_id` is a `UUID` shown to the outside world. Internal ids are
small and fast; external ids are unguessable. Never leak the first, never join
on the second.

**A policy can reach a user by two roads.** Directly (`user_policies`) or
through a group (`group_policies` + `user_groups`). `get_user_all_policies`
gathers both, and `PolicyService` then decides. Which brings us to the rule
that matters most:

> **DENY always wins.** If any policy that reaches the user says `DENY` for
> that resource and action, the answer is deny — no matter how many `ALLOW`s
> there are. This is enumerated exhaustively in the tests at the bottom of
> `policy_service.rs`, over all 961 combinations of the modelled policy space.

---

## 7. Multi-tenancy: one database, many customers

### The problem

You sell KeyRunes to Acme and to Globex. Both have a user called `admin`.
Neither may ever see the other's data — not by accident, not through a bug in
one forgotten `WHERE` clause.

### Three ways people solve this

1. **A column on every table** (`WHERE organization_id = ?`). Cheap, but one
   forgotten `WHERE` leaks everything. The failure mode is silent.
2. **A separate database per customer.** Perfectly safe, expensive, and
   migrating a thousand databases is its own career.
3. **A PostgreSQL schema per customer.** In between — and what KeyRunes does.

### How it works here

PostgreSQL has a setting called `search_path`: the list of schemas it looks in
when you write an unqualified table name. Think of it as the working directory
of a shell. `SELECT * FROM users` means "the `users` in whichever schema the
search path points at right now".

So every repository method does exactly this:

```rust
let mut tx = self.pool.begin().await?;                              // 1
sqlx::query(&format!("SET LOCAL search_path TO \"{}\"", namespace)) // 2
    .execute(&mut *tx).await?;
// 3. ordinary SQL from here on — no organization_id anywhere
```

1. Open a transaction. This matters: `SET LOCAL` is scoped to the transaction,
   so the setting cannot leak into the next request that borrows this pooled
   connection.
2. Point the search path at the tenant's schema.
3. Run completely ordinary SQL. The isolation is ambient.

Creating a tenant means creating a schema and applying
`migrations/tenant/001_init_tenant.sql` inside it.

### The catch, stated plainly

The namespace is **string-interpolated into SQL**. It is not a bind parameter —
it cannot be, because PostgreSQL does not allow parameters in `SET`.

That is why `OrganizationService::create_organization` refuses any namespace
that is not alphanumeric-plus-underscore. **That validation is the only thing
standing between this design and SQL injection.** If you ever add another path
that creates or accepts a namespace, it must apply the same check. Treat that
rule as load-bearing.

---

## 8. RBAC, ABAC, ReBAC, PBAC without the acronyms

The README advertises four access-control models. They sound like four
different engines; they are really four ways of answering one question.

**RBAC — Role-Based.** *"Editors may publish articles."* You get permissions
because of a **group** you are in. This is `groups` + `user_groups` +
`group_policies`. It is the model most systems need and the one KeyRunes
implements most completely.

**ABAC — Attribute-Based.** *"Anyone may approve an expense under €500, during
office hours, from the corporate network."* The decision depends on
**attributes** of the user, the resource, and the moment. This is the
`conditions` JSON column on `policies`.

**ReBAC — Relationship-Based.** *"You may edit a document if you are its
owner, or if its owner shared it with you."* The decision follows a **graph of
relationships** rather than a list of roles. Google Drive works this way.

**PBAC — Policy-Based.** The umbrella: express all of the above as policy
documents evaluated by one engine, rather than as four subsystems.

The shape in the database is deliberately generic — `resource`, `action`,
`effect`, `conditions` — precisely so one table can express all four. Today
`PolicyService` evaluates resource + action + effect; `conditions` is the seam
where the attribute and relationship rules grow.

---

## 9. Every dependency and why it is here

A dependency you cannot justify is a liability you have not noticed yet. Here
is the whole list.

### The spine

| Crate | What it does | Why here |
|---|---|---|
| **tokio** | The async runtime — the thing that actually runs `async fn`. Rust ships the syntax but no engine; this is the engine. | Everything async. |
| **axum** | Web framework built on tower. Routes, extractors, middleware. | The HTTP server. |
| **tower** / **tower-http** | The `Service` abstraction axum is built on, plus ready-made middleware. | `ServeDir` for `/static`, CORS, and `from_fn` middleware. |
| **sqlx** | Async SQL with **compile-time checked queries** and a migration runner. Not an ORM — you write SQL. | All database access; `sqlx::migrate!` runs migrations on boot. |
| **serde** / **serde_json** / **serde_with** | Turn Rust structs into JSON and back. `serde_with` adds helpers for awkward shapes. | Every request and response body. |

### Identity and secrets

| Crate | What it does | Why here |
|---|---|---|
| **argon2** | The password hashing function that won the Password Hashing Competition. Deliberately slow and memory-hard, so guessing is expensive. | Hashing every password. Its slowness is a feature — and the reason some test suites are excluded from mutation runs. |
| **password-hash** | The PHC string format (`$argon2id$v=19$...`) and the traits argon2 implements. | Storing and parsing hashes portably. |
| **josekit** | JOSE: JWT signing and verification. | `JwtService`. **Important:** `decode_with_verifier` checks the *signature only*. `exp` and `iss` are checked by hand in `verify_token` — they were once not, and expired tokens worked forever. |
| **secrecy** | `SecretString`: a wrapper that refuses to print itself in `Debug` output and zeroes memory on drop. | `domain::user::Password`, so a stray `dbg!` cannot leak a password into the logs. |
| **rand** | Cryptographically usable randomness. | Reset tokens, salts. |
| **uuid** | UUID generation and parsing. | Every `external_id`, and organization `secret_key`. |
| **hex** | Hex encoding. | Token formatting. |

### Presentation

| Crate | What it does | Why here |
|---|---|---|
| **tera** | HTML templating, Jinja2-like. | Everything in `templates/` — pages, error pages, and the password-reset email. |
| **lettre** | SMTP client. | `EmailService`. Optional at boot. |
| **utoipa** / **utoipa-swagger-ui** | Generate an OpenAPI document from annotations and serve Swagger UI. | `/swagger-ui` and `/api-docs/openapi.json`. |

### Plumbing

| Crate | What it does | Why here |
|---|---|---|
| **tracing** / **tracing-subscriber** | Structured logging with spans, plus `RUST_LOG`-style filtering. | `handler::logging`. |
| **anyhow** | One error type that can hold any error, with context. For application code where the caller just wants to know it failed. | Service and repository returns. |
| **thiserror** | Derives real error *enums* for cases where the caller must branch on the variant. | Typed errors where they matter. |
| **async-trait** | Lets traits have `async fn`. | Every repository trait — without it the trait objects do not compile. |
| **clap** | Command-line parsing with derive. | `src/bin/cli.rs`. |
| **chrono** | Dates and times with timezones. | Timestamps, token expiry. |
| **regex** | Regular expressions. | Email validation in `domain::user`. |
| **url** | URL parsing and validation. | Base URLs, redirects. |
| **dotenvy** | Loads `.env` into the environment. | Local development. |
| **futures** / **tokio-stream** | Combinators for futures and streams. | Concurrent work in services. |

### Development only

| Crate | What it does | Status |
|---|---|---|
| **proptest** | Property-based testing: generates inputs, shrinks failures. | **Used** — `tests/jwt_property_test.rs` |
| **exhaustive** | Enumerates *every* value of a modelled type. | **Used** — `policy_service.rs`, `jwt_service.rs`, `handler/auth.rs`, `handler/errors.rs`, `tests/admin_view_test.rs` |
| **fake** | Generates realistic fake names, emails, companies. | **Used** — `tests/common/factories/` |
| **serial_test** | `#[serial]` forces tests to run one at a time. | **Used** — the four database suites, which would otherwise fight over the same rows |
| **goose** | Load-testing framework. | **Used** — `tests/stress_test.rs` (needs a running server) |
| **base64** | Base64url encoding. | **Used** — forging JWTs byte by byte in the `jwt_service` tests |
| **rstest** | Fixtures and parameterised test cases. | **Declared, not yet used** — see [the testing guide](./testing.md#2-rstest--the-same-test-with-different-numbers) |
| **test-case** | Another parameterised-test macro. | **Declared, not used.** Overlaps with rstest; pick one. |
| **criterion** | Statistical benchmarking. | **Declared, not used** — there is no `benches/` directory. |
| **tokio-test** | Helpers for testing async code. | **Declared, not used.** |

> Four unused dev-dependencies is not a crisis, but it is four crates the
> supply chain is on the hook for. Either use them or drop them.

Mutation testing uses **cargo-mutants**, which is *not* in `Cargo.toml` — it is
a binary you install (`cargo install cargo-mutants --locked`), configured by
`.cargo/mutants.toml`.

---

## 10. Where do I put my new code?

A decision table for the question that actually comes up.

| You want to… | Put it in | And remember |
|---|---|---|
| add a JSON endpoint | `src/api/` | pick the right router in `main.rs`; that choice *is* the security |
| add a web page | `src/views/` + `templates/` | register the route in `main.rs` too |
| add a business rule | `src/services/` | no HTTP types here; return `anyhow::Result` |
| add a query | the trait in `src/repository/mod.rs`, then `sqlx_impl.rs` | start with `SET LOCAL search_path`, and update every mock in `tests/` |
| change the schema | a new file in `migrations/` | and `migrations/tenant/` if tenants need it too; then `make sqlx-prepare` |
| add a validated value type | `src/domain/` | make the constructor the only way in |
| add a CLI command | `src/bin/cli.rs` | it talks to services, not to SQL |
| protect an existing route | move it to another router in `main.rs` | there is no other place this is decided |

### Three traps this codebase has actually fallen into

They are all fixed; they are listed because the shape of each mistake is easy
to repeat.

1. **A public route that trusted its input.** `/api/register` accepted a
   `group` field and assigned it by name, so anyone could post
   `{"group": "superadmin"}`. Fixed by `constants::is_privileged_group`. The
   lesson: a route in `public_router` receives input from strangers, always.
2. **A token that never expired.** `verify_token` parsed `exp` and `iss` and
   then discarded both, because the JWT library only verifies the signature.
   A leaked token worked forever. The lesson: a library that "verifies" may
   verify less than you assume — read what it checks.
3. **Tests that tested copies of the code.** Two integration suites had a
   `mod test_handlers` that re-implemented the handlers they were meant to
   guard, so they stayed green while the real code broke. The lesson: if a test
   file contains no `use keyrunes::…`, it is testing nothing.

---

## Where next

- [Testing guide](./testing.md) — how the four kinds of test here work and when
  to reach for each.
- [Feature specs](./features/README.md) — locked designs for 2FA, WebAuthn and
  OIDC/SSO.
- `make help` — every task you can run.
- `/swagger-ui` on a running server — the live API reference.
