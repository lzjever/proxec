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
        .stdout(predicate::str::contains("Transparently proxy"))
        .stdout(predicate::str::contains("--disable-ipv6"))
        .stdout(predicate::str::contains("--no-proxy"));
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

#[test]
fn test_proxy_env_vars_are_ignored_with_warning() {
    Command::cargo_bin("proxec")
        .unwrap()
        .env("http_proxy", "http://127.0.0.1:9999")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("NO_PROXY")
        .arg("--proxy")
        .arg("socks://127.0.0.1:1080")
        .arg("true")
        .assert()
        .success()
        .stdout(predicate::str::contains("Ignoring system proxy environment variables"));
}

#[test]
fn test_no_proxy_invalid_cidr() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("--proxy")
        .arg("socks://127.0.0.1:1080")
        .arg("--no-proxy")
        .arg("192.168.0.0/99")
        .arg("true")
        .assert()
        .failure();
}
