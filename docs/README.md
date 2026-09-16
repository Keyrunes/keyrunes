# KeyRunes documentation

Written for people. If a page here only makes sense once you already know the
answer, it has failed and should be rewritten.

Everything follows the same shape, which is worth naming because it is the
thing that makes documentation stay useful:

> **Explain it to someone who does not work here.** Start with the problem in
> plain words. Reach for an analogy before reaching for jargon. Then show the
> mechanism. Then show the real code. Then say where people trip.
>
> The test is simple: if you cannot explain it simply, you do not understand it
> well enough yet — so go back to the code, not to the thesaurus.

---

## Start here

**New to the project?** Read them in this order.

| # | Guide | What you get | Time |
|---|---|---|---|
| 1 | [Architecture](./architecture.md) | What KeyRunes does, one request traced end to end, every directory and every dependency explained | ~25 min |
| 2 | [Testing](./testing.md) | The five testing techniques used here, which question each answers, and how to run them | ~25 min |
| 3 | [Feature specs](./features/README.md) | Locked designs for 2FA, WebAuthn and OIDC/SSO — not yet implemented | reference |

**Just need one answer?**

| I want to… | Go to |
|---|---|
| understand what this service is for | [Architecture §1](./architecture.md#1-what-keyrunes-actually-does) |
| see how a login actually flows | [Architecture §3](./architecture.md#3-one-request-all-the-way-down) |
| know where to put my new code | [Architecture §10](./architecture.md#10-where-do-i-put-my-new-code) |
| understand why there are two ids on every row | [Architecture §6](./architecture.md#6-the-data-model) |
| understand multi-tenancy | [Architecture §7](./architecture.md#7-multi-tenancy-one-database-many-customers) |
| know what a crate in `Cargo.toml` is for | [Architecture §9](./architecture.md#9-every-dependency-and-why-it-is-here) |
| write a test and not know which kind | [Testing §0](./testing.md#0-the-whole-guide-in-one-table) |
| read a mutation-testing report | [Testing §5](./testing.md#5-cargo-mutants--would-your-tests-notice) |
| run the test suite | [Testing §7](./testing.md#7-running-things) |

---

## The three-sentence version

KeyRunes is an access-control service. It answers two questions for other
systems — *who are you?* (authentication, a signed JWT) and *what may you do?*
(authorization, allow or deny) — so that no other system has to grow its own
opinion about either. It serves several unrelated customers from one database
by giving each its own PostgreSQL schema.

---

## What is elsewhere

| Where | What |
|---|---|
| [`README.md`](../README.md) | project pitch, features, quick start |
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | how to contribute |
| `make help` | every task you can run |
| `/swagger-ui` on a running server | the live API reference |
| `hurl/README.md` | how to run the end-to-end HTTP tests |
| `.cargo/mutants.toml` | mutation-testing scope, with a reason beside every exclusion |

---

## A note on the feature specs

`docs/features/` holds **locked specifications** for work that has not been
built yet. They are contracts, not descriptions: they say what 2FA, WebAuthn
and OIDC/SSO *will* do. Nothing in them ships today.

They are written in Portuguese; the guides above are in English, matching the
rest of the repository.
