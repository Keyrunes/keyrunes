# The testing guide

> Five techniques live in this repository. They look like five flavours of the
> same thing. They are not — each one answers a **different question**, and
> knowing which question you are asking is most of the skill.

---

## 0. The whole guide in one table

| Technique | The question it answers | Tool | Cost |
|---|---|---|---|
| Example test | "Does it work for this case I thought of?" | `#[test]` | free |
| Table test | "Does it work for these twelve cases, without twelve copies of the test?" | `rstest` | free |
| Property test | "Does the rule hold for a thousand cases I did **not** think of?" | `proptest` | seconds |
| Exhaustive test | "Does it hold for **every** case in a world small enough to walk?" | `exhaustive` | free |
| Mutation test | "Would any of the above **notice** if the code were wrong?" | `cargo-mutants` | minutes |

Read that last row again. The first four test the code. The fifth tests **the
tests**. It is the only one that can tell you your suite is decorative.

1. [Example tests](#1-example-tests--the-floor)
2. [rstest](#2-rstest--the-same-test-with-different-numbers)
3. [proptest](#3-proptest--cases-you-did-not-think-of)
4. [exhaustive](#4-exhaustive--every-case-in-a-small-world)
5. [cargo-mutants](#5-cargo-mutants--would-your-tests-notice)
6. [The supporting cast](#6-the-supporting-cast)
7. [Running things](#7-running-things)
8. [Recipes](#8-recipes)
9. [Traps](#9-traps-this-repository-has-actually-fallen-into)

---

## 1. Example tests — the floor

### The idea

You pick an input, you state the output you expect, you compare. This is the
test everyone already knows, and roughly 80% of this repository's suite.

### What it is good at

Being **specific**. When a login must return exactly 401 with exactly the body
`{"error":"invalid credentials"}`, an example test says so in a way anyone can
read. A property test could never be that concrete.

### What it is bad at

Your imagination is the ceiling. You test the empty string because you thought
of the empty string. Nobody thinks of a 200-byte body whose 199th byte is the
middle of a three-byte UTF-8 character — and that is the one that panicked in
production.

### In this repo

```rust
// src/views/admin.rs — the gate, extracted so it can be tested at all
pub fn may_view_admin(groups: &[String]) -> bool {
    groups.iter().any(|g| g == SUPERADMIN_GROUP || g == ADMIN_GROUP)
}
```

Notice the extraction. `admin_page` needs a live `PgPool` and cannot be called
from a unit test; the *decision* it makes does not. Pulling a pure function
out of an impure handler is the single highest-leverage move for testability
in this codebase.

---

## 2. rstest — the same test with different numbers

### The idea

You have written this, and you know you have:

```rust
#[test]
fn test_400() { assert_error(400, "Bad Request"); }
#[test]
fn test_401() { assert_error(401, "Unauthorized"); }
#[test]
fn test_403() { assert_error(403, "Forbidden"); }
```

Three tests, one idea, copied. Or you collapse them into a loop — which is
worse, because now one failing case fails "the test" and you have to read the
message to find out which.

`rstest` gives you the middle: **one function, many cases, each reported
separately.**

### The analogy

A recipe with a table of ingredient quantities instead of three near-identical
recipes. Same method; the amounts change.

### The mechanics

```rust
use rstest::rstest;

#[rstest]
#[case("/api/test/400", StatusCode::BAD_REQUEST, "Bad Request")]
#[case("/api/test/401", StatusCode::UNAUTHORIZED, "Unauthorized")]
#[case("/api/test/403", StatusCode::FORBIDDEN, "Forbidden")]
#[case("/api/test/404", StatusCode::NOT_FOUND, "Not Found")]
#[tokio::test]
async fn every_error_route_answers_with_its_own_status(
    #[case] path: &str,
    #[case] expected_status: StatusCode,
    #[case] expected_error: &str,
) {
    let app = create_test_app().await;
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), expected_status);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], expected_error);
}
```

`cargo test` now reports four separate tests:

```
every_error_route_answers_with_its_own_status::case_1 ... ok
every_error_route_answers_with_its_own_status::case_2 ... ok
every_error_route_answers_with_its_own_status::case_3 ... ok
every_error_route_answers_with_its_own_status::case_4 ... ok
```

That naming is the entire point. A loop gives you one red line; this gives you
`case_3`.

### The other half: fixtures

```rust
use rstest::{fixture, rstest};

#[fixture]
fn admin_user() -> User {
    UserFactory::new().username("admin").realistic_email().build()
}

#[rstest]
fn an_admin_may_open_the_console(admin_user: User) {
    assert!(may_view_admin(&["admin".to_string()]));
    assert_eq!(admin_user.username, "admin");
}
```

Ask for a fixture by naming it as a parameter and rstest builds it for you. It
is dependency injection for tests, and fixtures can depend on other fixtures.

### Multiplying cases

```rust
#[rstest]
fn no_group_combination_opens_the_gate_by_accident(
    #[values("users", "instructor", "administrators")] first: &str,
    #[values("users", "guest")] second: &str,
) { /* runs 3 × 2 = 6 times */ }
```

That is the cartesian product — and at that point you are one step away from
[exhaustive testing](#4-exhaustive--every-case-in-a-small-world), which does
it for you from the *type*.

### Status in this repo

`rstest = "0.26.1"` is in `[dev-dependencies]` and **is not yet used anywhere**.
The clearest place to start is `tests/all_errors_code.rs`, which currently
holds hand-rolled `for (path, status, code) in test_cases` loops — exactly the
shape rstest exists to replace.

---

## 3. proptest — cases you did not think of

### The idea

Stop describing *examples*. Describe the **rule**, and let the machine hunt for
a counter-example.

- Example test: "`verify(sign("ana"))` returns `"ana"`."
- Property test: "for **any** valid name, `verify(sign(name))` returns that
  name."

proptest generates hundreds of inputs, runs the rule against each, and if one
fails it does something genuinely clever: it **shrinks** the failure. It keeps
simplifying the input while the test keeps failing, so instead of reporting
`"aX9#$%mmm_ÿ23"` it reports `"\u{80}"` — the smallest thing that still breaks.
That shrunk value usually tells you the bug on sight.

### The analogy

An example test is checking that your bridge holds one specific lorry. A
property test drives ten thousand randomly-loaded lorries across it, and when
one falls through, it works out the lightest lorry that also falls through.

### The mechanics

```rust
use proptest::prelude::*;

/// A *strategy* — a recipe for generating values.
fn secret() -> impl Strategy<Value = String> {
    "[A-Za-z0-9]{32,64}"          // a regex is a strategy
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn every_claim_survives_a_round_trip(
        secret in secret(),
        user_id in 1i64..1_000_000,
    ) {
        let service = JwtService::new(&secret);
        let token = service.generate_token(user_id, /* … */).unwrap();
        let claims = service.verify_token(&token).unwrap();
        prop_assert_eq!(claims.sub, user_id.to_string());
    }
}
```

Three things to note:

- `in` binds a **strategy**, not a value. `1i64..1_000_000` is a range
  strategy; a regex literal is a string strategy.
- Use `prop_assert_eq!`, not `assert_eq!`. The `prop_` versions return a
  failure instead of panicking, which is what lets shrinking work properly.
- `with_cases(48)` keeps the suite fast. The default is 256; crank it up
  locally when you are hunting something.

### The two shapes of property that pay off

**Round trip.** Something goes in, comes out the other side, and must be
unchanged. Encode/decode, serialize/deserialize, sign/verify. If it differs,
one of the halves is wrong.

**Robustness ("no input may panic").** Take arbitrary bytes, throw them at a
public function, and assert only that it does not crash. This is how
`tests/jwt_property_test.rs` guards the token parser — `verifying_arbitrary_text_never_panics`
does not care what the answer is, only that there *is* an answer.

That second shape is the cheapest real security testing you can buy. Every
function that parses attacker-controlled bytes deserves one.

### In this repo

`tests/jwt_property_test.rs` — ~13 properties over `JwtService`, split into a
round-trip contract and a robustness contract. `JwtService` was chosen because
it is pure (no database) **and** it is the security boundary every protected
route passes through. That combination is what makes a good property-testing
target.

---

## 4. exhaustive — every case in a small world

### The idea

proptest *samples*. If the space of inputs is small enough, why sample? Walk
all of it.

You cannot enumerate every `String`. But you can enumerate every combination of
"which of these 9 kinds of `Accept` header" × "which of these 7 kinds of path" —
63 cases — and then you are not testing a sample, you are testing a **proof for
that model**.

### The analogy

proptest is a survey: ask a thousand random people and infer. exhaustive is a
census of a village of sixty: ask everyone, and stop inferring.

### The mechanics

```rust
use exhaustive::{Exhaustive, exhaustive_test};

#[derive(Debug, Clone, Copy, PartialEq, Exhaustive)]
enum AcceptShape {
    Absent,
    Json,
    JsonAmongOthers,   // a browser list that happens to include JSON
    StarJson,
    Html,
    StarStar,
    Empty,
    Garbage,
    NonUtf8,           // bytes where to_str() fails
}

#[exhaustive_test]
fn wants_json_reads_only_the_accept_header(accept: AcceptShape) {
    // runs once per variant, automatically
}
```

`#[derive(Exhaustive)]` teaches the crate to list every value of your enum.
`#[exhaustive_test]` turns each parameter into a loop over those values, so
three parameters give you the full cartesian product for free.

> **Number types are deliberately not supported.** There is no `u32:
> Exhaustive`, because four billion cases is not a test, it is a hang. This
> constraint is the feature: it forces you to *model* the input space instead
> of enumerating it.

### The skill: modelling

This is where the technique lives or dies. You are not listing values, you are
listing the **kinds of value that behave differently**.

For an HTTP `Accept` header, the interesting kinds are: absent, exactly JSON,
JSON inside a browser list, the `*/json` wildcard, HTML, `*/*`, empty,
syntactic garbage, and bytes that are not UTF-8. Nine. That covers every branch
the parser has, plus the failure modes a hand-written test forgets.

Give each variant a doc comment explaining *why it is a distinct kind*. If you
cannot write that sentence, the variant is a duplicate.

### The second skill: expressing the expectation without restating the code

The trap is writing a test that re-implements the function and compares. That
passes always and proves nothing. The way out is to put the answer **on the
model**:

```rust
impl AcceptShape {
    /// Only a header that actually names JSON asks for JSON.
    fn asks_for_json(self) -> bool {
        matches!(self, Self::Json | Self::JsonAmongOthers | Self::StarJson)
    }
}

#[exhaustive_test]
fn the_404_body_format_follows_route_and_accept(path: PathShape, accept: AcceptShape) {
    // …
    assert_eq!(served_json, path.is_api() || accept.asks_for_json());
}
```

`asks_for_json` is declared once, next to the variants, by a human deciding
what *ought* to happen. The assertion then reads as a rule, not as a mirror.

### In this repo

| Where | What is enumerated | Cases |
|---|---|---|
| `src/handler/errors.rs` | path shape × Accept header → JSON or HTML 404 | 63 |
| `src/handler/auth.rs` | Authorization header × Cookie header → extracted token | 64 |
| `src/services/policy_service.rs` | resource × action × effect patterns → allow/deny | 961 |
| `src/services/jwt_service.rs` | claim name × tampering kind → accept/reject | — |
| `tests/admin_view_test.rs` | up to three group memberships → gate opens or not | 343 |

The `policy_service` suite is the one to read first. **DENY beating ALLOW** is
the most important rule in the product, and it is checked against all 961
combinations rather than the four a human would have written.

---

## 5. cargo-mutants — would your tests notice?

### Start with the uncomfortable question

Your suite is green and coverage says 96%. Now: if someone flipped a `!` in
your authorization middleware, would a test fail?

Coverage cannot tell you. Coverage records that a line **ran**. It has no
opinion about whether anything **checked what the line did**. A test that calls
a function and asserts nothing gives you 100% coverage of it.

### The idea

Mutation testing changes the code on purpose and reruns your suite.

1. Take one expression. Change it: `>` becomes `>=`, `&&` becomes `||`, a `!`
   is deleted, a function body is replaced by `Ok(())`.
2. Run the tests.
3. If a test fails, the mutant is **caught** — good, something was watching.
4. If every test still passes, the mutant **survived** — that line is
   unguarded.

A surviving mutant is not a bug. It is a **place where a bug could hide**.

### The analogy

Coverage is checking that the security guard walked past every door. Mutation
testing is trying the handles while they walk past.

### Why "mutagen" is not what we use

The famous Rust crate for this is [`mutagen`](https://github.com/llogiq/mutagen).
It is **unmaintained and nightly-only**. `cargo-mutants` is its de-facto
successor, runs on stable Rust, and needs no changes to your source. People
still say "mutagen" the way they say "hoover"; this repo runs cargo-mutants.

### Running it

```bash
cargo install cargo-mutants --locked   # a binary, not a dependency
cargo mutants                          # the whole configured run
cargo mutants --list                   # what it would try, without trying it
cargo mutants -f 'replace > with >= in truncate'   # one mutant, by name
```

Results land in `mutants.out/`:

| File | Meaning |
|---|---|
| `caught.txt` | a test failed. Good. |
| `missed.txt` | **read this one.** Every line here is unguarded. |
| `timeout.txt` | the mutant hung — usually an infinite loop, effectively caught |
| `unviable.txt` | the mutant did not compile. Not your problem. |

Exit code `2` means something survived, so it works as a CI gate.

### Reading a survivor

A real one from this repository's first run:

```
MISSED src/views/admin.rs:25:8: delete ! in admin_page
```

Line 25 is the gate on the admin console:

```rust
if !may_view_admin(&user.groups) {
    return Redirect::to("/dashboard").into_response();
}
```

Delete the `!` and the meaning inverts: admins are bounced to the dashboard and
everyone else walks into the admin page. **The entire suite stayed green.**

The fix is never to silence it — it is to write the missing test, and the
survivor names it for you: drive the handler once as an admin and assert the
page renders, once as an ordinary user and assert the redirect. You need
**both** directions. One alone leaves the inverted version passing, which is
exactly how this survived in the first place.

### The configuration, and why scope matters

`.cargo/mutants.toml` — note the path, cargo-mutants reads it from `.cargo/`,
not the repo root.

Every mutant costs a full rebuild plus a full test run. If your suite takes
18 seconds, two hundred mutants is an hour. So the config narrows the field to
code reachable by **fast, database-free** tests:

```toml
examine_globs = [
    "src/services/jwt_service.rs",
    "src/services/policy_service.rs",
    "src/handler/errors.rs",
    # …
]

additional_cargo_test_args = [
    "--lib",
    "--test", "jwt_property_test",
    "--test", "admin_view_test",
    # …
]
```

The exclusions are documented in the file itself, with reasons — Argon2 suites
are excluded because Argon2 is *designed* to be slow; the Postgres suites
because a mutant cannot wait for a database.

> **Keep the two lists in step.** Mutating a file no selected test can reach
> reports survivors that say nothing about test quality — noise that trains
> you to ignore the report.

The file also records **known survivors** and why each is left alone: a
self-check whose only happy-path behaviour is the `Ok` it returns, a logger
that configures global state. Anything *not* on that list is a real gap until
proven otherwise.

### What it found here

| | first run | after the gaps were closed |
|---|---|---|
| Mutants | 104 | 102 |
| Caught | 61 | **75** |
| **Survived** | **20** | **4** |
| Unviable | 23 | 23 |
| Score (of viable) | 75% | **95%** |

The percentage is the least interesting part. What the twenty survivors
actually said:

- **All four middleware gates were no-ops as far as the suite was concerned.**
  `require_auth`, `optional_auth`, `require_superadmin` and
  `require_org_key_or_superadmin` could each be replaced by
  `Default::default()` with nothing failing. The only thing tested in that file
  was `extract_bearer_token` — never the gates that call it.
- **The admin console gate could be inverted**, as shown above.
- **Two integration suites contained a `mod test_handlers`** that
  re-implemented the handlers they were meant to guard. They tested a copy of
  the code. They would have stayed green through any change to the real thing.

None of that is the kind of thing you find by reading, and none of it shows up
as a coverage gap.

The four survivors that remain are listed in `.cargo/mutants.toml` with an
argument for each — two health self-checks whose only happy-path behaviour is
the `Ok` they return, a logger that configures global state, and a comparison
that would need a live `UserService` to reach. Anything **not** on that list is
a real gap until proven otherwise.

---

## 6. The supporting cast

### `fake` — realistic test data

`tests/common/factories/` wraps `fake` in builders:

```rust
let user = UserFactory::new()
    .organization_id(7)
    .realistic_email()
    .build();
```

The value is not the randomness, it is the **defaults**. When a test only cares
about `organization_id`, the factory fills the other eight fields with
something plausible and the test says only what it means.

### `serial_test` — tests that must not race

```rust
#[tokio::test]
#[serial]
async fn counting_users_sees_only_this_tenant() { /* … */ }
```

`cargo test` runs tests in parallel by default. Four suites here hit a real
PostgreSQL and would otherwise trip over each other's rows. `#[serial]` forces
them into single file.

If you add a test that touches the database, it needs this attribute. A
flaky-under-load test is almost always a missing `#[serial]`.

### `hurl/` — end-to-end over real HTTP

Hurl files are plain text: a request, then assertions on the response.

```
POST {{host}}/api/login
{ "identity": "admin", "password": "{{password}}", "namespace": "public" }

HTTP 200
[Asserts]
jsonpath "$.token" exists
```

These run against a **live server with a real database** — the only tests that
prove the whole stack works together, including migrations, routing and
templates.

```bash
make test-hurl        # server must already be running
```

### `goose` — load testing

`tests/stress_test.rs` drives many simulated users at a running server. Not part
of `cargo test`; run it deliberately with `make test-stress`.

---

## 7. Running things

```bash
# Everything that does not need a server
make test                 # cargo test
make test-unit            # unit tests only
make test-integration     # tests/ only

# Needs a live server
make test-hurl            # end-to-end HTTP
make test-stress          # load test

# Quality gates
make lint                 # clippy -D warnings
make fmt-check
cargo mutants             # mutation testing
```

Two environment facts that will otherwise waste an afternoon:

- **`SQLX_OFFLINE=true`** lets sqlx compile against the cached metadata in
  `.sqlx/` instead of a live database. The pre-commit hook sets it. If you
  change a query, run `make sqlx-prepare` or the next offline build fails.
- The database suites need Postgres. `make docker-up` then `make db-reset`.

The repo's own `CLAUDE.md` asks for commands to be prefixed with `rtk`
(`rtk cargo test`), a wrapper that compresses tool output.

---

## 8. Recipes

### "I fixed a bug"

Write the failing test **first**, watch it fail, then fix. A test you never saw
fail is a test you have not verified.

Then ask which kind it should be:

- Is it one specific input? Example test.
- Is it one of a family? `rstest` with a `#[case]` per member.
- Is it a rule that should hold generally? `proptest`.
- Is the input space small and enumerable? `exhaustive`.

### "I wrote a new service method"

1. Add the method to the repository trait if it needs storage.
2. Update **every** mock implementation in `tests/` — the compiler will list
   them.
3. Test the service against the mock; no database needed.
4. If the method has branches, run `cargo mutants -f '<method name>'` and check
   that each branch has something watching it.

### "I want to know if my tests are any good"

```bash
cargo mutants
cat mutants.out/missed.txt
```

Every line is a question: *what test would have caught this?* Write that test.

### "I'm adding an exhaustive suite"

1. Write the enum. One variant per **behaviour**, not per value.
2. Doc-comment each variant with why it is distinct.
3. Put the expected answer on the model (`fn asks_for_json`), not in the
   assertion.
4. Include the ugly cases: empty, garbage, non-UTF-8, wrong case, extra
   whitespace, lookalikes (`"administrators"` when you mean `"admin"`).
5. Say the count in the doc comment — "7 × 9 = 63 combinations". It tells the
   next reader how much of the space this really covers.

---

## 9. Traps this repository has actually fallen into

**Tests that test a copy of the code.** Two suites re-implemented the handlers
they were meant to guard. Green forever, worthless forever.
*Check: does the file contain `use keyrunes::…`? If not, it tests nothing.*

**Tautological tests.** `tests/admin_view_test.rs` once contained eleven tests
like `let user_id: i64 = -1; assert!(user_id < 0);`. Not one line referenced the
project.
*Check: could this test fail if the production code changed? If not, delete it.*

**One-sided guard tests.** Testing that a member is admitted, but never that a
non-member is refused. Deleting the `!` then passes.
*Check: for every boolean gate, is there a test on each side?*

**Trusting a library's idea of "verify".** `josekit`'s `decode_with_verifier`
checks the **signature only**. `exp` and `iss` came back parsed and were
discarded, so expired tokens worked forever.
*Check: read what the library actually validates, then test the thing it does
not.*

**Coverage as a finish line.** Every line of `handler/auth.rs` was executed by
the suite, and all four gates in it could still be replaced by
`Default::default()` without a single failure. The lines ran; nothing checked
what they did.
*Check: coverage tells you what ran; only mutation testing tells you what was
watched.*

---

## Where next

- [Architecture guide](./architecture.md) — what the code you are testing does.
- `.cargo/mutants.toml` — the mutation scope and the known-survivor list.
- `tests/jwt_property_test.rs` — the clearest proptest example here.
- `src/handler/errors.rs` (bottom) — the clearest exhaustive example here.
