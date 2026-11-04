//! Keyrunes: a multi-tenant identity, group and policy service.
//!
//! The crate is layered: HTTP JSON handlers (`api`), server-rendered HTML
//! views (`views`), request plumbing and authorization middleware
//! (`handler`), validated primitives (`domain`), persistence traits with
//! their `sqlx` implementations (`repository`) and business logic on top of
//! them (`services`). `main.rs` wires everything together.

/// HTTP JSON API handlers (all routes live under `/api`).
pub mod api;
/// Values shared across layers: namespaces, group names, length limits.
pub mod constants;
/// Validated newtypes (`Email`, `Password`) and core entity structs.
pub mod domain;
/// Request middleware (JWT auth, API keys), error responses and logging.
pub mod handler;
/// Persistence traits and their PostgreSQL (`sqlx`) implementations.
pub mod repository;
/// Business logic orchestrating the repositories.
pub mod services;
/// Server-rendered HTML views (Tera templates).
pub mod views;

pub use repository::*;
pub use services::*;
