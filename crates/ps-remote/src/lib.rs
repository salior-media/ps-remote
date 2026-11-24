// SPDX-License-Identifier: AGPL-3.0-only
//! The ps-remote service (`docs/SERVICE.md`): plays a linked console in a browser over WebRTC, through a
//! local API on loopback.

pub mod api;
pub mod bridge;
pub mod input;
pub mod runner;
