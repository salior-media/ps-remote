// SPDX-License-Identifier: AGPL-3.0-only
//! Forward error correction for the video stream: Cauchy Reed-Solomon over GF(2⁸). Ported from chiaki-ng
//! `lib/src/fec.c` (LicenseRef-AGPL-3.0-only-OpenSSL), which calls Jerasure.
//!
//! The console encodes with Jerasure's `cauchy_original_coding_matrix(k, m, 8)`: parity row `i`, data
//! column `j` holds `1 / (i ⊕ (m + j))` in GF(2⁸), with gf-complete's default polynomial for w = 8,
//! 0x11d. That matrix is fixed by the console, so a general Reed-Solomon crate (which builds a different
//! one) would not decode its frames; this crate builds the same one.
//!
//! A frame is `k` data units followed by `m` parity units, all `unit_size` bytes. Any `k` of the `k + m`
//! units recover the data.

mod gf;

pub const WORD_SIZE: u32 = 8;
/// Jerasure refuses `k + m > 2^w`; so do we.
pub const MAX_UNITS: usize = 1 << WORD_SIZE;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FecError {
    #[error("a frame needs at least one data unit and one parity unit (k = {k}, m = {m})")]
    Empty { k: usize, m: usize },
    #[error("k + m = {0} units is more than GF(2^8) can index ({MAX_UNITS})")]
    TooManyUnits(usize),
    #[error("expected {expected} units, got {got}")]
    UnitCount { expected: usize, got: usize },
    #[error("unit {index} is {len} bytes; every unit must be {unit_size}")]
    UnitSize { index: usize, len: usize, unit_size: usize },
    #[error("{lost} of {total} units are missing; at most {m} can be recovered")]
    TooManyErasures { lost: usize, total: usize, m: usize },
}

/// The code for one frame shape: `k` data units and `m` parity units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fec {
    k: usize,
    m: usize,
    /// `m` rows of `k` coefficients.
    parity: Vec<u8>,
}

impl Fec {
    pub fn new(k: usize, m: usize) -> Result<Self, FecError> {
        if k == 0 || m == 0 {
            return Err(FecError::Empty { k, m });
        }
        if k + m > MAX_UNITS {
            return Err(FecError::TooManyUnits(k + m));
        }
        let parity = (0..m)
            .flat_map(|i| (0..k).map(move |j| gf::div(1, (i ^ (m + j)) as u8)))
            .collect();
        Ok(Self { k, m, parity })
    }

    pub fn k(&self) -> usize {
        self.k
    }

    pub fn m(&self) -> usize {
        self.m
    }

    /// Row `r` of the full generator: the identity for a data unit, a Cauchy row for a parity unit.
    fn generator_row(&self, unit: usize) -> Vec<u8> {
        if unit < self.k {
            (0..self.k).map(|j| u8::from(j == unit)).collect()
        } else {
            let r = unit - self.k;
            self.parity[r * self.k..(r + 1) * self.k].to_vec()
        }
    }

    /// The `m` parity units for `data` (chiaki-ng `chiaki_fec_encode`).
    pub fn encode(&self, data: &[&[u8]]) -> Result<Vec<Vec<u8>>, FecError> {
        if data.len() != self.k {
            return Err(FecError::UnitCount { expected: self.k, got: data.len() });
        }
        let unit_size = data[0].len();
        check_sizes(data.iter().copied().enumerate(), unit_size)?;
        Ok((0..self.m)
            .map(|r| combine(&self.parity[r * self.k..(r + 1) * self.k], data, unit_size))
            .collect())
    }

    /// The `k` data units, recovered from whichever units arrived (chiaki-ng `chiaki_fec_decode`).
    ///
    /// `units` has one entry per unit, data first then parity; `None` marks one that was lost. Like
    /// Jerasure, the first `k` units that arrived are used.
    pub fn decode(&self, units: &[Option<&[u8]>]) -> Result<Vec<Vec<u8>>, FecError> {
        let total = self.k + self.m;
        if units.len() != total {
            return Err(FecError::UnitCount { expected: total, got: units.len() });
        }
        let present: Vec<(usize, &[u8])> =
            units.iter().enumerate().filter_map(|(i, u)| u.map(|u| (i, u))).collect();
        if present.len() < self.k {
            return Err(FecError::TooManyErasures { lost: total - present.len(), total, m: self.m });
        }
        let unit_size = present[0].1.len();
        check_sizes(present.iter().copied(), unit_size)?;
        if (0..self.k).all(|i| units[i].is_some()) {
            return Ok((0..self.k).map(|i| units[i].expect("checked present").to_vec()).collect());
        }
        let chosen = &present[..self.k];
        let rows: Vec<Vec<u8>> = chosen.iter().map(|(i, _)| self.generator_row(*i)).collect();
        let inverse = gf::invert(&rows).expect("any k rows of a Cauchy-extended identity are independent");
        let received: Vec<&[u8]> = chosen.iter().map(|(_, u)| *u).collect();
        Ok(inverse.iter().map(|row| combine(row, &received, unit_size)).collect())
    }
}

fn check_sizes<'a>(units: impl Iterator<Item = (usize, &'a [u8])>, unit_size: usize) -> Result<(), FecError> {
    for (index, u) in units {
        if u.len() != unit_size {
            return Err(FecError::UnitSize { index, len: u.len(), unit_size });
        }
    }
    Ok(())
}

/// Σ coef[j] · units[j], byte by byte, in GF(2⁸).
fn combine(coefs: &[u8], units: &[&[u8]], unit_size: usize) -> Vec<u8> {
    let mut out = vec![0u8; unit_size];
    for (&c, unit) in coefs.iter().zip(units) {
        if c == 0 {
            continue;
        }
        for (o, &b) in out.iter_mut().zip(*unit) {
            *o ^= gf::mul(c, b);
        }
    }
    out
}
