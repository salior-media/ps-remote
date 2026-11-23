// SPDX-License-Identifier: AGPL-3.0-only
//! A fixed-size window that turns out-of-order packets back into order. Ported from chiaki-ng
//! `lib/src/reorderqueue.c` (LicenseRef-AGPL-3.0-only-OpenSSL).
//!
//! chiaki-ng reports dropped elements through a callback. Here, every call that can drop returns the
//! dropped elements instead, so the caller decides what to do with them.

use crate::seqnum::SeqNum;

/// What to do when a new element doesn't fit in the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropStrategy {
    /// Drop the oldest elements to make room (chiaki-ng `..._DROP_STRATEGY_BEGIN`).
    Begin,
    /// Drop the new element (chiaki-ng `..._DROP_STRATEGY_END`, its default).
    End,
}

#[derive(Debug)]
pub struct ReorderQueue<S: SeqNum, T> {
    slots: Vec<Option<T>>,
    begin: S,
    count: u64,
    pub drop_strategy: DropStrategy,
}

impl<S: SeqNum, T> ReorderQueue<S, T> {
    /// A window of `2^size_exp` slots, expecting `start` next.
    pub fn new(size_exp: u32, start: S) -> Self {
        Self {
            slots: std::iter::repeat_with(|| None).take(1 << size_exp).collect(),
            begin: start,
            count: 0,
            drop_strategy: DropStrategy::End,
        }
    }

    pub fn size(&self) -> u64 {
        self.slots.len() as u64
    }

    /// How many slots the window currently spans, filled or not.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The sequence number pulled next.
    pub fn begin(&self) -> S {
        self.begin
    }

    /// Slots are addressed by the sequence number's value masked to the size, as in chiaki-ng.
    fn index(&self, seq: S) -> usize {
        (seq.raw() as usize) & (self.slots.len() - 1)
    }

    fn slot(&mut self, seq: S) -> &mut Option<T> {
        let i = self.index(seq);
        &mut self.slots[i]
    }

    fn ge(a: S, b: S) -> bool {
        a == b || a.gt(b)
    }

    /// Adds an element. Returns whatever was dropped: the new element itself if it is a duplicate, older
    /// than the window, or doesn't fit under [`DropStrategy::End`]; or the oldest elements under
    /// [`DropStrategy::Begin`].
    pub fn push(&mut self, seq: S, value: T) -> Vec<(S, T)> {
        let size = self.size();
        let mut end = self.begin.wrapping_add_n(self.count);
        if Self::ge(seq, self.begin) && seq.lt(end) {
            let slot = self.slot(seq);
            if slot.is_some() {
                return vec![(seq, value)];
            }
            *slot = Some(value);
            return Vec::new();
        }
        if seq.lt(self.begin) {
            return vec![(seq, value)];
        }
        if !Self::ge(seq, end) {
            // Exactly half the number space away: the order is undefined. Rebase an empty queue that
            // drops from the front; otherwise drop the element (as chiaki-ng does, rather than abort).
            if self.count == 0 && self.drop_strategy == DropStrategy::Begin {
                self.begin = seq;
                end = seq;
            } else {
                return vec![(seq, value)];
            }
        }
        let mut dropped = Vec::new();
        let new_end = seq.wrapping_add_n(1);
        let mut total_end = end.wrapping_add_n(size - self.count);
        if total_end.lt(new_end) {
            if self.drop_strategy == DropStrategy::End {
                return vec![(seq, value)];
            }
            while self.count > 0 && total_end.lt(new_end) {
                let head = self.begin;
                if let Some(v) = self.slot(head).take() {
                    dropped.push((head, v));
                }
                self.begin = self.begin.wrapping_add_n(1);
                self.count -= 1;
                total_end = end.wrapping_add_n(size - self.count);
            }
            if self.count == 0 {
                self.begin = seq;
            }
        }
        let mut end = self.begin.wrapping_add_n(self.count);
        while end.lt(new_end) {
            *self.slot(end) = None;
            self.count += 1;
            end = self.begin.wrapping_add_n(self.count);
        }
        *self.slot(seq) = Some(value);
        dropped
    }

    /// The next element in order, if it has arrived.
    pub fn pull(&mut self) -> Option<(S, T)> {
        if self.count == 0 {
            return None;
        }
        let head = self.begin;
        let value = self.slot(head).take()?;
        self.begin = self.begin.wrapping_add_n(1);
        self.count -= 1;
        Some((head, value))
    }

    /// The element `index` places after `begin`, if it has arrived. `index` is an offset, not a
    /// sequence number.
    pub fn peek(&self, index: u64) -> Option<(S, &T)> {
        if index >= self.count {
            return None;
        }
        let seq = self.begin.wrapping_add_n(index);
        self.slots[self.index(seq)].as_ref().map(|v| (seq, v))
    }

    /// Removes the element at offset `index` and returns it. `begin` doesn't move; if it was the last
    /// slot, the window shrinks back to the last element that is still there.
    pub fn drop_at(&mut self, index: u64) -> Option<(S, T)> {
        if index >= self.count {
            return None;
        }
        let seq = self.begin.wrapping_add_n(index);
        let value = self.slot(seq).take()?;
        if index == self.count - 1 {
            while self.count > 0 {
                let last = self.begin.wrapping_add_n(self.count - 1);
                if self.slots[self.index(last)].is_some() {
                    break;
                }
                self.count -= 1;
            }
        }
        Some((seq, value))
    }

    /// Everything still in the window, in order (chiaki-ng calls the drop callback with these in `fini`).
    pub fn drain(&mut self) -> Vec<(S, T)> {
        let out = (0..self.count)
            .filter_map(|i| {
                let seq = self.begin.wrapping_add_n(i);
                self.slot(seq).take().map(|v| (seq, v))
            })
            .collect();
        self.count = 0;
        out
    }
}
