// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Integration tests.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_help_flag() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Transparently proxy"));
}

#[test]
fn test_version_flag() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("proxec"));
}

#[test]
fn test_missing_proxy() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("echo")
        .arg("hello")
        .assert()
        .failure();
}
