// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Integration tests.

use assert_cmd::Command;
use std::process::{Command as StdCommand, Stdio};
use std::thread;
use std::time::Duration;

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
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

#[test]
fn test_proxec_exits_when_traced_program_exits() {
    Command::cargo_bin("proxec")
        .unwrap()
        .arg("--proxy")
        .arg("socks://127.0.0.1:1080")
        .arg("sh")
        .arg("-c")
        .arg("exit 0")
        .assert()
        .success();
}

#[test]
fn test_sigint_terminates_traced_process_group() {
    let marker = format!("proxec-shutdown-test-{}", std::process::id());
    let proxec_bin = assert_cmd::cargo::cargo_bin("proxec");
    let child = StdCommand::new(proxec_bin)
        .arg("--proxy")
        .arg("socks://127.0.0.1:1080")
        .arg("python3")
        .arg("-c")
        .arg("import time; time.sleep(30)")
        .arg(&marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    thread::sleep(Duration::from_millis(500));
    kill(Pid::from_raw(child.id() as i32), Signal::SIGINT).unwrap();

    let output = child.wait_with_output().unwrap();
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert_eq!(output.status.code(), Some(128 + libc::SIGINT));
    assert!(combined.contains("terminating traced process group"));

    thread::sleep(Duration::from_millis(300));
    let pgrep = StdCommand::new("pgrep")
        .arg("-af")
        .arg(&marker)
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&pgrep.stdout).trim().is_empty(),
        "found leftover traced process: {}",
        String::from_utf8_lossy(&pgrep.stdout)
    );
}
