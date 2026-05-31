// SPDX-FileCopyrightText: 2026-Present Gaussian Technologies
// SPDX-License-Identifier: Apache-2.0

//! # gm-obs
//!
//! Observability for GaussMatrix (GaussInteract-SPECS §VIII.A): a
//! Prometheus-compatible [`Metrics`] registry and **structured emission of the
//! audit log** for ingestion by a SIEM.
//!
//! The audit log (`gm-store`) is the platform's compliance backbone; this crate
//! turns its durable, hash-chained entries into structured records and streams
//! them to a pluggable [`SiemSink`], and exposes counters/gauges in the
//! Prometheus text exposition format. A live Prometheus HTTP exporter and
//! OpenTelemetry traces (spanning the front-end → shard → store path) are wired
//! behind features later.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(rust_2018_idioms)]

pub mod metrics;
pub mod siem;

pub use metrics::Metrics;
pub use siem::{stream_audit, AuditRecord, SiemSink, VecSink, WriterSink};
