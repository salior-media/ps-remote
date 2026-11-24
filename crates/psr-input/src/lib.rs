// SPDX-License-Identifier: AGPL-3.0-only
//! Controller input for Remote Play: the controller's state, and the feedback packets that carry it to
//! the console. Ported from chiaki-ng `lib/src/controller.c`, `feedback.c` and `feedbacksender.c`.
//!
//! Nothing here touches a socket or a clock: [`sender::FeedbackSender`] is given the time and returns the
//! packets to send, and psr-lan's stream encrypts and sends them.

pub mod controller;
pub mod feedback;
pub mod sender;
