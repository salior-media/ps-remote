// SPDX-License-Identifier: AGPL-3.0-only
//! Decides which feedback packets go out, and when. Ported from chiaki-ng `lib/src/feedbacksender.c`
//! (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! chiaki-ng runs this as a thread that sleeps on a condition variable. Here it is a state machine: give
//! it the controller state as it changes, call [`FeedbackSender::poll`] with the time, and send what it
//! returns; [`FeedbackSender::next_deadline`] says when to call it again. What goes out, and when, is
//! chiaki-ng's:
//!
//! - A **state** packet when the sticks or motion change, and at least every 200 ms.
//! - A **history** packet for each new button or touch event, carrying the recent events too. Each event
//!   takes the next sequence number, and a packet carries the number of its newest event, so the console
//!   applies each event once however many packets repeat it.
//! - The last history packet again 20, 50, 100 and 200 ms after it went out, while nothing new follows:
//!   history packets are not acknowledged, and a lost release would leave a button held.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::controller::ControllerState;
use crate::feedback::{FeedbackState, HistoryBuffer};

/// chiaki-ng `FEEDBACK_STATE_TIMEOUT_MAX_MS`.
pub const STATE_INTERVAL_MAX: Duration = Duration::from_millis(200);
/// chiaki-ng `FEEDBACK_HISTORY_BUFFER_SIZE`.
const HISTORY_SIZE: usize = 0x10;
/// chiaki-ng `FEEDBACK_HISTORY_RESEND_EVENT_COUNT`: events repeated in every history packet.
pub const HISTORY_RESEND_EVENTS: usize = 8;
/// chiaki-ng `CHIAKI_FEEDBACK_HISTORY_PACKET_QUEUE_SIZE`.
const QUEUE_SIZE: usize = 0x40;
/// chiaki-ng `feedback_history_tail_ms`.
pub const HISTORY_TAIL: [Duration; 4] =
    [Duration::from_millis(20), Duration::from_millis(50), Duration::from_millis(100), Duration::from_millis(200)];

/// A packet to send: hand it to psr-takion's `Sender::feedback_state` or `Sender::feedback_history`.
#[derive(Debug, Clone, PartialEq)]
pub enum Feedback {
    State { seq_num: u16, state: FeedbackState },
    History { seq_num: u16, event_count: u8, events: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryPacket {
    seq_num: u16,
    event_count: u8,
    events: Vec<u8>,
}

/// chiaki-ng `ChiakiFeedbackSender`.
#[derive(Debug)]
pub struct FeedbackSender {
    state: ControllerState,
    /// The state last sent in a state packet.
    state_sent: ControllerState,
    /// The state the history was last recorded against.
    state_recorded: ControllerState,
    changed: bool,
    state_seq_num: u16,
    last_state_at: Instant,
    history: HistoryBuffer,
    /// The number the next event takes.
    history_seq_num: u16,
    queue: VecDeque<HistoryPacket>,
    last_history: Option<HistoryPacket>,
    last_history_at: Instant,
    /// How many of [`HISTORY_TAIL`]'s repeats have gone out since the last new history packet.
    tail_sent: usize,
    queue_overflows: u64,
}

impl FeedbackSender {
    /// Starts idle at `now` (chiaki-ng `chiaki_feedback_sender_init`).
    pub fn new(now: Instant) -> Self {
        Self {
            state: ControllerState::default(),
            state_sent: ControllerState::default(),
            state_recorded: ControllerState::default(),
            changed: false,
            state_seq_num: 0,
            last_state_at: now,
            history: HistoryBuffer::new(HISTORY_SIZE),
            history_seq_num: 0,
            queue: VecDeque::new(),
            last_history: None,
            last_history_at: now,
            tail_sent: HISTORY_TAIL.len(),
            queue_overflows: 0,
        }
    }

    /// History packets dropped because the queue was full (chiaki-ng logs these).
    pub fn queue_overflows(&self) -> u64 {
        self.queue_overflows
    }

    /// chiaki-ng `chiaki_feedback_sender_set_controller_state`: records the change's events, one history
    /// packet each. Nothing is sent until [`FeedbackSender::poll`].
    pub fn set_controller_state(&mut self, state: &ControllerState) {
        if self.state.equals(state) {
            return;
        }
        self.state = *state;
        let prev = self.state_recorded;
        let (history_seq_num, queue, overflows) =
            (&mut self.history_seq_num, &mut self.queue, &mut self.queue_overflows);
        self.history.record_state(&prev, state, |history| {
            *history_seq_num = history_seq_num.wrapping_add(1);
            // chiaki-ng `feedback_sender_flush_history_locked`: the whole buffer, numbered by its newest
            // event, then only the newest few are kept for the packets after.
            let packet = HistoryPacket {
                seq_num: history_seq_num.wrapping_sub(1),
                event_count: history.len() as u8,
                events: history.format(),
            };
            if queue.len() == QUEUE_SIZE {
                // The numbering still holds: the next packet's number moves by every event since.
                queue.pop_front();
                *overflows += 1;
            }
            queue.push_back(packet);
            history.truncate(HISTORY_RESEND_EVENTS);
        });
        self.state_recorded = *state;
        self.changed = true;
    }

    /// When [`FeedbackSender::poll`] has something to send next.
    pub fn next_deadline(&self) -> Instant {
        if self.changed || !self.queue.is_empty() {
            return self.last_state_at.min(self.last_history_at);
        }
        let state_due = self.last_state_at + STATE_INTERVAL_MAX;
        match self.tail_due() {
            Some(tail) => state_due.min(tail),
            None => state_due,
        }
    }

    fn tail_due(&self) -> Option<Instant> {
        self.last_history.as_ref()?;
        HISTORY_TAIL.get(self.tail_sent).map(|d| self.last_history_at + *d)
    }

    /// Everything due by `now`, in the order chiaki-ng's thread would send it (each round: a state packet,
    /// then a history packet). Queued history packets all go out at once, as chiaki-ng sends them without
    /// waiting between them.
    pub fn poll(&mut self, now: Instant) -> Vec<Feedback> {
        let mut out = Vec::new();
        loop {
            let timed_out = now >= self.last_state_at + STATE_INTERVAL_MAX || self.tail_due().is_some_and(|t| now >= t);
            if self.queue.is_empty() && !self.changed && !timed_out {
                break;
            }
            let mut send_state = now.saturating_duration_since(self.last_state_at) >= STATE_INTERVAL_MAX;
            if self.changed {
                self.changed = false;
                // chiaki-ng: nothing a state packet carries changed, so none is sent, even when one is due.
                send_state = !self.state.same_sticks_and_motion(&self.state_sent);
            }
            let history = if let Some(p) = self.queue.pop_front() {
                self.last_history = Some(p.clone());
                self.last_history_at = now;
                self.tail_sent = 0;
                Some(p)
            } else if self.tail_due().is_some_and(|t| now >= t) {
                self.tail_sent += 1;
                self.last_history.clone()
            } else {
                None
            };
            if send_state {
                out.push(Feedback::State { seq_num: self.state_seq_num, state: FeedbackState::from(&self.state) });
                self.state_seq_num = self.state_seq_num.wrapping_add(1);
                self.state_sent = self.state;
                self.last_state_at = now;
            }
            if let Some(p) = history {
                out.push(Feedback::History { seq_num: p.seq_num, event_count: p.event_count, events: p.events });
            }
        }
        out
    }
}
