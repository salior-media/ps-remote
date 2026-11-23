// SPDX-License-Identifier: AGPL-3.0-only
//! GF(2⁸) with the polynomial x⁸ + x⁴ + x³ + x² + 1 (0x11d), gf-complete's default for w = 8, using
//! log and antilog tables built at compile time with the generator 2.

const POLY: u16 = 0x11d;

const fn tables() -> ([u8; 512], [u8; 256]) {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= POLY;
        }
        i += 1;
    }
    // Doubling the table lets mul skip a modulo.
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    (exp, log)
}

const TABLES: ([u8; 512], [u8; 256]) = tables();
const EXP: [u8; 512] = TABLES.0;
const LOG: [u8; 256] = TABLES.1;

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 { 0 } else { EXP[LOG[a as usize] as usize + LOG[b as usize] as usize] }
}

/// a / b. Panics on b = 0; every caller divides by a value it knows is non-zero.
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "division by zero in GF(2^8)");
    if a == 0 { 0 } else { EXP[LOG[a as usize] as usize + 255 - LOG[b as usize] as usize] }
}

/// The inverse of a square matrix, by Gauss-Jordan elimination; `None` if it is singular.
pub fn invert(rows: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let n = rows.len();
    let mut a: Vec<Vec<u8>> = rows.to_vec();
    let mut inv: Vec<Vec<u8>> = (0..n).map(|i| (0..n).map(|j| u8::from(i == j)).collect()).collect();
    for col in 0..n {
        let pivot = (col..n).find(|&r| a[r][col] != 0)?;
        a.swap(col, pivot);
        inv.swap(col, pivot);
        let scale = div(1, a[col][col]);
        for j in 0..n {
            a[col][j] = mul(a[col][j], scale);
            inv[col][j] = mul(inv[col][j], scale);
        }
        for r in 0..n {
            let f = a[r][col];
            if r == col || f == 0 {
                continue;
            }
            for j in 0..n {
                a[r][j] ^= mul(f, a[col][j]);
                inv[r][j] ^= mul(f, inv[col][j]);
            }
        }
    }
    Some(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_non_zero_element_has_an_inverse() {
        for a in 1..=255u8 {
            assert_eq!(mul(a, div(1, a)), 1, "a = {a}");
        }
    }

    #[test]
    fn known_products_for_0x11d() {
        // 2 · 0x80 overflows once and is reduced by 0x11d: 0x100 ⊕ 0x11d = 0x1d.
        assert_eq!(mul(2, 0x80), 0x1d);
        assert_eq!(mul(3, 7), 9);
        assert_eq!(mul(0, 0xff), 0);
    }

    #[test]
    fn inverse_times_matrix_is_the_identity() {
        let m = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 10]];
        let inv = invert(&m).unwrap();
        for (i, row) in m.iter().enumerate() {
            for j in 0..3 {
                let v = row.iter().zip(&inv).fold(0u8, |acc, (&a, inv_row)| acc ^ mul(a, inv_row[j]));
                assert_eq!(v, u8::from(i == j));
            }
        }
    }
}
