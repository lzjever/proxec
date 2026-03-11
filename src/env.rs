// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: GPL-2.0-only

//! Runtime environment handling.

const PROXY_ENV_VARS: [&str; 8] = [
    "http_proxy",
    "HTTP_PROXY",
    "https_proxy",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyEnvCleanup {
    ignored_vars: Vec<String>,
}

impl ProxyEnvCleanup {
    pub fn ignored_vars(&self) -> &[String] {
        &self.ignored_vars
    }

    pub fn has_ignored_vars(&self) -> bool {
        !self.ignored_vars.is_empty()
    }
}

pub fn clear_proxy_env() -> ProxyEnvCleanup {
    let mut ignored_vars = Vec::new();

    for key in PROXY_ENV_VARS {
        if std::env::var_os(key).is_some() {
            ignored_vars.push(key.to_string());
            unsafe {
                std::env::remove_var(key);
            }
        }
    }

    ProxyEnvCleanup { ignored_vars }
}
