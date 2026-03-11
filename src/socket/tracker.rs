// proxec - Transparent Proxy Executor
// Copyright (C) 2024 proxec contributors
// SPDX-License-Identifier: MIT

//! Socket state tracking for stream socket based connect redirection.

use nix::unistd::Pid;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{IpAddr, SocketAddr};

/// Information about an intercepted socket.
#[derive(Debug, Clone)]
pub struct SocketInfo {
    /// Original destination address.
    pub dest: SocketAddr,
}

#[derive(Debug, Clone, Copy)]
struct PendingSocket {
    domain: i32,
    sock_type: i32,
}

/// Thread-safe socket tracker.
///
/// We only redirect `connect()` for fd that was created by
/// `socket(AF_INET/AF_INET6, SOCK_STREAM, ...)`.
pub struct SocketTracker {
    fd_dest: HashMap<(i32, i32), SocketInfo>, // (tgid, fd) -> dest
    inode_dest: HashMap<String, SocketInfo>,  // socket inode -> dest
    fd_inode: HashMap<(i32, i32), String>,    // (tgid, fd) -> socket inode
    tid_to_tgid: HashMap<i32, i32>,
    pending_socket: HashMap<i32, PendingSocket>,
    stream_fds: HashSet<(i32, i32)>, // (tgid, fd)
}

impl SocketTracker {
    pub fn new() -> Self {
        Self {
            fd_dest: HashMap::new(),
            inode_dest: HashMap::new(),
            fd_inode: HashMap::new(),
            tid_to_tgid: HashMap::new(),
            pending_socket: HashMap::new(),
            stream_fds: HashSet::new(),
        }
    }

    pub fn socket_enter(&mut self, pid: Pid, domain: i32, sock_type: i32) {
        self.pending_socket
            .insert(pid.as_raw(), PendingSocket { domain, sock_type });
    }

    pub fn socket_exit(&mut self, pid: Pid, ret_fd: i32) {
        let tid = pid.as_raw();
        let Some(pending) = self.pending_socket.remove(&tid) else {
            return;
        };
        if ret_fd < 0 {
            return;
        }
        if !is_stream_inet_socket(pending.domain, pending.sock_type) {
            return;
        }
        let tgid = self.resolve_tgid(tid);
        self.stream_fds.insert((tgid, ret_fd));
        tracing::debug!(
            "Tracked stream socket (tid={}, tgid={}, fd={}, domain={}, type=0x{:x})",
            tid,
            tgid,
            ret_fd,
            pending.domain,
            pending.sock_type
        );
    }

    pub fn close_enter(&mut self, pid: Pid, fd: i32) {
        let tgid = self.resolve_tgid(pid.as_raw());
        self.stream_fds.remove(&(tgid, fd));
        self.fd_dest.remove(&(tgid, fd));
        if let Some(inode) = self.fd_inode.remove(&(tgid, fd)) {
            self.inode_dest.remove(&inode);
        }
    }

    pub fn is_stream_socket_fd(&mut self, pid: Pid, fd: i32) -> bool {
        let tgid = self.resolve_tgid(pid.as_raw());
        self.stream_fds.contains(&(tgid, fd))
    }

    pub fn mark_stream_socket_fd(&mut self, pid: Pid, fd: i32) {
        let tgid = self.resolve_tgid(pid.as_raw());
        self.stream_fds.insert((tgid, fd));
    }

    pub fn insert_dest(&mut self, pid: Pid, fd: i32, info: SocketInfo) {
        let tgid = self.resolve_tgid(pid.as_raw());
        self.fd_dest.insert((tgid, fd), info);
    }

    pub fn bind_inode(&mut self, pid: Pid, fd: i32, inode: String) {
        let tgid = self.resolve_tgid(pid.as_raw());
        if let Some(info) = self.fd_dest.get(&(tgid, fd)).cloned() {
            self.inode_dest.insert(inode.clone(), info);
        }
        self.fd_inode.insert((tgid, fd), inode);
    }

    pub fn get_by_pid_fd(&self, pid: i32, fd: i32) -> Option<&SocketInfo> {
        self.fd_dest.get(&(pid, fd))
    }

    pub fn get_by_inode(&self, inode: &str) -> Option<&SocketInfo> {
        self.inode_dest.get(inode)
    }

    pub fn cleanup_process(&mut self, pid: Pid) {
        let tid = pid.as_raw();
        self.pending_socket.remove(&tid);
        let tgid = self
            .tid_to_tgid
            .remove(&tid)
            .or_else(|| read_tgid_from_proc_status(tid))
            .unwrap_or(tid);

        // Thread exits are common in Chromium/Electron. Do not tear down
        // process-wide socket state unless the thread-group itself is gone.
        if tid != tgid && process_exists(tgid) {
            return;
        }

        self.fd_dest.retain(|(p, _), _| *p != tgid);
        self.fd_inode.retain(|(p, _), inode| {
            let keep = *p != tgid;
            if !keep {
                self.inode_dest.remove(inode);
            }
            keep
        });
        self.stream_fds.retain(|(p, _)| *p != tgid);
        self.tid_to_tgid.retain(|_, mapped_tgid| *mapped_tgid != tgid);
    }

    pub fn stats(&self) -> usize {
        self.fd_dest.len()
    }

    pub fn entries(&self) -> impl Iterator<Item = (&i32, &SocketInfo)> {
        self.fd_dest.iter().map(|((pid, _fd), info)| (pid, info))
    }

    fn resolve_tgid(&mut self, tid: i32) -> i32 {
        if let Some(tgid) = self.tid_to_tgid.get(&tid) {
            return *tgid;
        }
        let tgid = read_tgid_from_proc_status(tid).unwrap_or(tid);
        self.tid_to_tgid.insert(tid, tgid);
        tgid
    }
}

impl Default for SocketTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn is_stream_inet_socket(domain: i32, sock_type: i32) -> bool {
    const AF_INET: i32 = libc::AF_INET;
    const AF_INET6: i32 = libc::AF_INET6;
    const SOCK_STREAM: i32 = libc::SOCK_STREAM;
    (domain == AF_INET || domain == AF_INET6) && (sock_type & SOCK_STREAM) == SOCK_STREAM
}

/// Find TCP inode by connection tuple in /proc/net/tcp.
pub fn find_inode_by_conn(
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
) -> Option<String> {
    let local_ip = match local_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return None,
    };
    let remote_ip = match remote_ip {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return None,
    };

    let file = fs::File::open("/proc/net/tcp").ok()?;
    let reader = std::io::BufReader::new(file);
    let local_pattern = format!(
        "{:02X}{:02X}{:02X}{:02X}:{:04X}",
        local_ip.octets()[3],
        local_ip.octets()[2],
        local_ip.octets()[1],
        local_ip.octets()[0],
        local_port
    );
    let remote_pattern = format!(
        "{:02X}{:02X}{:02X}{:02X}:{:04X}",
        remote_ip.octets()[3],
        remote_ip.octets()[2],
        remote_ip.octets()[1],
        remote_ip.octets()[0],
        remote_port
    );

    use std::io::BufRead;
    for line in reader.lines().skip(1) {
        let line = line.ok()?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        if parts[1] == local_pattern && parts[2] == remote_pattern && parts[9] != "0" {
            return Some(parts[9].to_string());
        }
    }
    None
}

pub fn read_socket_inode(pid: Pid, fd: i32) -> Option<String> {
    let tgid = read_tgid_from_proc_status(pid.as_raw()).unwrap_or(pid.as_raw());
    let link = fs::read_link(format!("/proc/{tgid}/fd/{fd}")).ok()?;
    let link = link.to_string_lossy();
    let inode = link.strip_prefix("socket:[")?.strip_suffix(']')?;
    Some(inode.to_string())
}

/// Find process (tgid) that owns a socket inode.
pub fn find_pid_fd_by_inode(inode: &str) -> Option<(i32, i32)> {
    let search = format!("socket:[{inode}]");
    for entry in fs::read_dir("/proc").ok()? {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let pid: i32 = match name.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let fd_glob = format!("/proc/{pid}/fd");
        if let Ok(fd_entries) = fs::read_dir(fd_glob) {
            for fd_entry in fd_entries.flatten() {
                if let Ok(link) = fs::read_link(fd_entry.path()) {
                    if link.to_string_lossy() == search {
                        let fd_name = fd_entry.file_name().to_string_lossy().to_string();
                        if let Ok(fd) = fd_name.parse::<i32>() {
                            return Some((pid, fd));
                        }
                    }
                }
            }
        }
    }
    None
}

fn read_tgid_from_proc_status(tid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            return value.trim().parse().ok();
        }
    }
    None
}

fn process_exists(pid: i32) -> bool {
    fs::metadata(format!("/proc/{pid}")).is_ok()
}

pub fn probe_socket_is_stream(pid: Pid, fd: i32) -> std::io::Result<bool> {
    let target_pid = read_tgid_from_proc_status(pid.as_raw()).unwrap_or(pid.as_raw());
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, target_pid, 0) as i32 };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let dupfd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd, fd, 0) as i32 };
    unsafe {
        libc::close(pidfd);
    }
    if dupfd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut sock_type: libc::c_int = 0;
    let mut optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(
            dupfd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut sock_type as *mut _ as *mut libc::c_void,
            &mut optlen as *mut _,
        ) == 0
    };
    unsafe {
        libc::close(dupfd);
    }

    if !ok {
        return Err(std::io::Error::last_os_error());
    }

    Ok((sock_type & libc::SOCK_STREAM) == libc::SOCK_STREAM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_inode_exposes_dest_lookup() {
        let mut tracker = SocketTracker::new();
        let pid = Pid::from_raw(std::process::id() as i32);
        let fd = 7;
        let inode = "12345".to_string();
        let dest: SocketAddr = "1.2.3.4:443".parse().unwrap();

        tracker.insert_dest(pid, fd, SocketInfo { dest });
        tracker.bind_inode(pid, fd, inode.clone());

        assert_eq!(tracker.get_by_inode(&inode).unwrap().dest, dest);

        tracker.close_enter(pid, fd);
        assert!(tracker.get_by_inode(&inode).is_none());
    }
}
