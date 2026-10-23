//! The TeamCraft push gateway: holds the APNs and FCM credentials of the published store apps and
//! forwards the sealed wake-ups of any TeamCraft server to them. It sees device tokens, opaque
//! server IDs and ciphertext; it cannot read or forge a wake-up (docs/design.md). The HTTP contract
//! is docs/api.md.

pub mod api;
pub mod app;
pub mod auth;
pub mod config;
pub mod limits;
pub mod maintenance;
pub mod metrics;
pub mod ops;
pub mod providers;
pub mod store;
pub mod tokens;
