// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! ML-DSA-65 signature verification for a browser, from `aws-lc-rs`.
//!
//! Built for `wasm32-unknown-emscripten` by `build.sh`. The module exports one
//! function, `mldsa_verify`, plus `malloc` and `free` so that the caller can put
//! the key, the message and the signature into the module's memory. It checks
//! the signature primitive only; it is not the verifier.

use aws_lc_rs::signature::{UnparsedPublicKey, ML_DSA_65};

/// Returns 1 if `sig` is a valid ML-DSA-65 signature of `msg` under the public
/// key `pk` (the 1,952-byte raw key), and 0 in every other case (a bad
/// signature, a key or signature of the wrong length, a null pointer with a
/// non-zero length).
///
/// # Safety
/// Each pointer must be valid for reading the stated number of bytes.
#[no_mangle]
pub unsafe extern "C" fn mldsa_verify(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    unsafe fn slice<'a>(p: *const u8, n: usize) -> Option<&'a [u8]> {
        if n == 0 {
            Some(&[])
        } else if p.is_null() {
            None
        } else {
            Some(core::slice::from_raw_parts(p, n))
        }
    }
    let (Some(pk), Some(msg), Some(sig)) = (slice(pk, pk_len), slice(msg, msg_len), slice(sig, sig_len)) else {
        return 0;
    };
    i32::from(UnparsedPublicKey::new(&ML_DSA_65, pk).verify(msg, sig).is_ok())
}

fn main() {}
