// =============================================================================
//    Copyright (c) 2025 - 2026 Haixing Hu.
//
//    SPDX-License-Identifier: Apache-2.0
//
//    Licensed under the Apache License, Version 2.0.
// =============================================================================
//! Compile-fail fixture for missing `no_mut` on borrowed sensitive data.

use qubit_redact::domain::RedactMut as _;
use qubit_redact_derive::Redact;

#[derive(Redact)]
struct BorrowedUser<'a> {
    #[redact(level = "secret")]
    password: &'a str,
}

fn main() {
    let user = BorrowedUser {
        password: "raw-password",
    };
    let _ = user.into_redacted();
}
