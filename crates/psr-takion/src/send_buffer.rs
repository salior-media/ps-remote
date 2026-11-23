// SPDX-License-Identifier: AGPL-3.0-only
//! Reliable messages waiting for the console's acknowledgement. Ported from the bookkeeping half of
//! chiaki-ng `lib/src/takionsendbuffer.c`. Resending on a timer belongs to the transport loop, which
//! comes with the session step.

use crate::TakionError;
use crate::seqnum::SeqNum;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub seq_num: u32,
    pub tries: u32,
    pub datagram: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendBuffer {
    capacity: usize,
    pending: Vec<Pending>,
}

impl SendBuffer {
    pub fn new(capacity: usize) -> Self {
        Self { capacity, pending: Vec::with_capacity(capacity) }
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn pending(&self) -> &[Pending] {
        &self.pending
    }

    /// chiaki-ng `chiaki_takion_send_buffer_push`: refuses when full, or when the sequence number is
    /// already waiting.
    pub fn push(&mut self, seq_num: u32, datagram: Vec<u8>) -> Result<(), TakionError> {
        if self.pending.len() >= self.capacity {
            return Err(TakionError::SendBufferFull(self.capacity));
        }
        if self.pending.iter().any(|p| p.seq_num == seq_num) {
            return Err(TakionError::DuplicateSeqNum(seq_num));
        }
        self.pending.push(Pending { seq_num, tries: 0, datagram });
        Ok(())
    }

    /// chiaki-ng `chiaki_takion_send_buffer_ack`: an acknowledgement of `seq_num` covers it and every
    /// earlier one (in serial order). Returns the sequence numbers removed, in buffer order.
    pub fn ack(&mut self, seq_num: u32) -> Vec<u32> {
        let (acked, kept): (Vec<Pending>, Vec<Pending>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|p| p.seq_num == seq_num || p.seq_num.lt(seq_num));
        self.pending = kept;
        acked.into_iter().map(|p| p.seq_num).collect()
    }
}
