// SPDX-License-Identifier: AGPL-3.0-only
// Ported from chiaki-ng `test/fec.c` (LicenseRef-AGPL-3.0-only-OpenSSL). Its 64 cases are real frames;
// vectors/fec_cases.txt is generated from `test/fec_test_cases.inl` by scripts/convert_fec_cases.py.

use base64::Engine;
use psr_fec::{Fec, FecError};

struct Case {
    k: usize,
    m: usize,
    erasures: Vec<usize>,
    units: Vec<Vec<u8>>,
}

fn cases() -> Vec<Case> {
    include_str!("vectors/fec_cases.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            let (k, m): (usize, usize) = (f[0].parse().unwrap(), f[1].parse().unwrap());
            let erasures = f[2].split(',').map(|e| e.parse().unwrap()).collect();
            let unit_size: usize = f[3].parse().unwrap();
            let bytes = base64::engine::general_purpose::STANDARD.decode(f[4]).unwrap();
            assert_eq!(bytes.len(), unit_size * (k + m), "{line:.40}");
            let units = bytes.chunks(unit_size).map(<[u8]>::to_vec).collect();
            Case { k, m, erasures, units }
        })
        .collect()
}

#[test]
fn all_64_chiaki_ng_frames_decode() {
    let cases = cases();
    assert_eq!(cases.len(), 64);
    for (n, c) in cases.iter().enumerate() {
        let fec = Fec::new(c.k, c.m).unwrap();
        let received: Vec<Option<&[u8]>> = (0..c.k + c.m)
            .map(|i| (!c.erasures.contains(&i)).then_some(&c.units[i][..]))
            .collect();
        let data = fec.decode(&received).unwrap_or_else(|e| panic!("case {n}: {e}"));
        assert_eq!(data.len(), c.k, "case {n}");
        for (i, (got, want)) in data.iter().zip(&c.units).enumerate() {
            assert_eq!(got, want, "case {n}, data unit {i}");
        }
    }
}

/// Not in chiaki-ng: these frames were encoded by a real console, so re-encoding their recovered data must
/// give back every parity unit that arrived. That proves our matrix is the console's matrix, not only one
/// that happens to decode. (A lost unit's bytes in the capture are not real data, so they are skipped.)
#[test]
fn encoding_the_data_reproduces_the_consoles_parity() {
    let mut compared = 0;
    for (n, c) in cases().iter().enumerate() {
        let fec = Fec::new(c.k, c.m).unwrap();
        let received: Vec<Option<&[u8]>> = (0..c.k + c.m)
            .map(|i| (!c.erasures.contains(&i)).then_some(&c.units[i][..]))
            .collect();
        let data = fec.decode(&received).unwrap();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let parity = fec.encode(&refs).unwrap();
        for r in (0..c.m).filter(|r| !c.erasures.contains(&(c.k + r))) {
            assert_eq!(parity[r], c.units[c.k + r], "case {n}, parity unit {r}");
            compared += 1;
        }
    }
    assert!(compared > 0, "no parity unit arrived in any case, so nothing was compared");
    eprintln!("compared {compared} parity units that the console sent");
}

#[test]
fn every_way_of_losing_up_to_m_units_recovers_the_data() {
    let (k, m) = (5, 3);
    let fec = Fec::new(k, m).unwrap();
    let data: Vec<Vec<u8>> = (0..k).map(|i| (0..64).map(|b| (i * 37 + b * 11) as u8).collect()).collect();
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
    let all: Vec<Vec<u8>> = data.iter().cloned().chain(fec.encode(&refs).unwrap()).collect();
    for lost in 0u32..(1 << (k + m)) {
        if lost.count_ones() as usize > m {
            continue;
        }
        let received: Vec<Option<&[u8]>> =
            (0..k + m).map(|i| (lost & (1 << i) == 0).then_some(&all[i][..])).collect();
        assert_eq!(fec.decode(&received).unwrap(), data, "lost mask {lost:#b}");
    }
}

#[test]
fn losing_more_than_m_is_an_error_not_garbage() {
    let fec = Fec::new(4, 2).unwrap();
    let unit = [1u8; 8];
    let received = [None, None, None, Some(&unit[..]), Some(&unit[..]), Some(&unit[..])];
    assert_eq!(fec.decode(&received), Err(FecError::TooManyErasures { lost: 3, total: 6, m: 2 }));
}

#[test]
fn shapes_jerasure_refuses_are_refused() {
    assert_eq!(Fec::new(200, 57), Err(FecError::TooManyUnits(257)));
    assert!(Fec::new(0, 1).is_err());
    assert!(Fec::new(1, 0).is_err());
}

#[test]
fn units_of_different_sizes_are_refused() {
    let fec = Fec::new(2, 1).unwrap();
    let (a, b) = ([0u8; 4], [0u8; 5]);
    assert!(matches!(fec.encode(&[&a, &b]), Err(FecError::UnitSize { index: 1, .. })));
}
