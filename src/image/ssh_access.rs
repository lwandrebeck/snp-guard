//! Key-only SSH access baked into the encrypted rootfs at conversion time.
//!
//! Stock cloud images ship without SSH host keys and with every account
//! locked: both are expected to come from cloud-init on first boot.  A CVM
//! has no datasource (no seed disk, no metadata service), so cloud-init's
//! ds-identify disables itself, sshd fails its `sshd -t` pre-start check, and
//! the guest boots with no way in.
//!
//! Feeding cloud-init from a host-provided seed disk would work, but that
//! input is unmeasured and cloud-init runs as root after the disk is unlocked:
//! whoever controls the host could add users or run commands inside the CVM.
//! Instead, everything is written into the rootfs here, which is only readable
//! once attestation has released the disk key:
//!
//! - a user with key-only login and passwordless sudo,
//! - removal of any host keys inherited from the source image, plus a unit
//!   that runs `ssh-keygen -A` before sshd, so each CVM generates its own
//!   host keys on first boot and the private halves never leave the guest,
//! - `/etc/cloud/cloud-init.disabled`, so the host cannot inject anything later.

use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Key algorithms accepted in the authorized_keys file.
const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

const HOSTKEYS_UNIT_NAME: &str = "snpguard-ssh-hostkeys.service";

/// Pulled in by ssh.service and ordered before it, so it also runs when sshd
/// is socket-activated.  `ssh-keygen -A` only creates missing keys, so later
/// boots are a no-op.
const HOSTKEYS_UNIT: &str = "\
[Unit]
Description=Generate missing SSH host keys (snpguard)
Before=ssh.service

[Service]
Type=oneshot
ExecStart=/usr/bin/ssh-keygen -A

[Install]
WantedBy=ssh.service
";

const NETWORK_CONFIG_PATH: &str = "/etc/systemd/network/80-snpguard-dhcp.network";

/// Same shape as cloud-init's fallback: DHCP on the wired NICs.
const NETWORK_CONFIG: &str = "\
[Match]
Name=en* eth*

[Network]
DHCP=yes
";

/// Validated SSH access settings, checked before any expensive work starts.
pub struct SshAccess {
    /// Explicit login name; `None` means the distro's customary default user.
    user: Option<String>,
    /// Normalized authorized_keys content: one public key per line.
    authorized_keys: String,
}

impl SshAccess {
    pub fn from_args(
        authorized_keys: Option<PathBuf>,
        user: Option<String>,
    ) -> Result<Option<Self>> {
        let Some(path) = authorized_keys else {
            if user.is_some() {
                bail!("--ssh-user requires --ssh-authorized-keys");
            }
            return Ok(None);
        };
        if let Some(name) = &user {
            validate_user_name(name)?;
        }
        Ok(Some(Self {
            user,
            authorized_keys: read_authorized_keys(&path)?,
        }))
    }

    /// Login name to create: the explicit one, or `default_user`.
    pub fn user_or<'a>(&'a self, default_user: &'a str) -> &'a str {
        self.user.as_deref().unwrap_or(default_user)
    }
}

/// Accepts POSIX-portable login names only.  The name is interpolated into
/// shell commands run inside the target, so this is also the injection guard.
fn validate_user_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == '_');
    let rest_ok =
        chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !first_ok || !rest_ok || name.len() > 32 {
        bail!(
            "Invalid --ssh-user {:?}: use 1-32 characters from [a-z0-9_-], starting with a letter or '_'",
            name
        );
    }
    if name == "root" {
        bail!("--ssh-user root is not allowed: log in as a regular user and use sudo");
    }
    Ok(())
}

fn read_authorized_keys(path: &Path) -> Result<String> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read authorized keys file {:?}", path))?;
    parse_authorized_keys(&content)
        .with_context(|| format!("Invalid authorized keys file {:?}", path))
}

/// Returns the keys one per line, without comments or blank lines.  Rejects
/// private keys outright: uploading one into the image by mistake would leak it
/// to anyone who can later log in.
fn parse_authorized_keys(content: &str) -> Result<String> {
    if content.contains("PRIVATE KEY") {
        bail!("this looks like a private key; pass the public key (.pub) instead");
    }
    let mut keys = Vec::new();
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // authorized_keys lines may start with options (e.g. from="..."), so
        // look for "<key type> <base64 blob>" anywhere rather than at column 0.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let has_key = tokens
            .windows(2)
            .any(|w| KEY_TYPES.contains(&w[0]) && is_key_blob(w[1]));
        if !has_key {
            bail!(
                "line {}: expected an OpenSSH public key (one of {})",
                idx + 1,
                KEY_TYPES.join(", ")
            );
        }
        keys.push(line);
    }
    if keys.is_empty() {
        bail!("no public keys found");
    }
    Ok(keys.join("\n") + "\n")
}

/// Every OpenSSH public key blob is base64 and well over 16 characters.
fn is_key_blob(s: &str) -> bool {
    s.len() >= 16
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

fn is_file(g: &guestfs::Handle, path: &str) -> Result<bool> {
    g.is_file(
        path,
        guestfs::IsFileOptArgs {
            followsymlinks: Some(true),
        },
    )
    .map_err(|e| anyhow!("Failed to check for {}: {:?}", path, e))
}

fn is_dir(g: &guestfs::Handle, path: &str) -> Result<bool> {
    g.is_dir(
        path,
        guestfs::IsDirOptArgs {
            followsymlinks: Some(true),
        },
    )
    .map_err(|e| anyhow!("Failed to check for {}: {:?}", path, e))
}

/// Provisions key-only SSH access in the target rootfs mounted at `/`.
pub fn provision(g: &guestfs::Handle, access: &SshAccess, default_user: &str) -> Result<()> {
    let user = access.user_or(default_user);
    let sh = |cmd: &str| -> Result<String> {
        g.sh(cmd)
            .map_err(|e| anyhow!("Failed to execute '{}': {:?}", cmd, e))
    };

    if !is_file(g, "/usr/sbin/sshd")? {
        bail!("--ssh-authorized-keys given, but the image has no OpenSSH server (/usr/sbin/sshd)");
    }

    println!("Provisioning SSH access for user '{user}'...");

    // `*` rather than useradd's default `!`: both rule out password logins, but
    // sshd treats a `!`-prefixed hash as a locked account and refuses even key
    // authentication when UsePAM is off.
    sh(&format!(
        "id -u {user} >/dev/null 2>&1 || useradd --create-home --shell /bin/bash {user}; \
         usermod -p '*' {user}; \
         if getent group sudo >/dev/null; then usermod -aG sudo {user}; fi"
    ))?;

    let home = sh(&format!("getent passwd {user} | cut -d: -f6"))?;
    let home = home.trim();
    let home_ok = home.starts_with('/')
        && home
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'.' | b'-'));
    if !home_ok {
        bail!("Unexpected home directory for '{user}': {home:?}");
    }

    let ssh_dir = format!("{home}/.ssh");
    let keys_path = format!("{ssh_dir}/authorized_keys");
    g.mkdir_p(&ssh_dir)
        .map_err(|e| anyhow!("Failed to mkdir {}: {:?}", ssh_dir, e))?;
    g.write(&keys_path, access.authorized_keys.as_bytes())
        .map_err(|e| anyhow!("Failed to write {}: {:?}", keys_path, e))?;
    sh(&format!(
        "chown -R {user}: '{ssh_dir}' && chmod 700 '{ssh_dir}' && chmod 600 '{keys_path}'"
    ))?;

    // The account has no usable password, so sudo must not ask for one.
    if is_dir(g, "/etc/sudoers.d")? {
        let sudoers = format!("/etc/sudoers.d/90-snpguard-{user}");
        g.write(
            &sudoers,
            format!("{user} ALL=(ALL) NOPASSWD:ALL\n").as_bytes(),
        )
        .map_err(|e| anyhow!("Failed to write {}: {:?}", sudoers, e))?;
        g.chmod(0o440, &sudoers)
            .map_err(|e| anyhow!("Failed to chmod {}: {:?}", sudoers, e))?;
        sh(&format!("visudo -cf '{sudoers}'"))?;
    } else {
        println!("WARN: sudo is not installed in the image; '{user}' will have no root access");
    }

    // Host keys copied from the source image would be shared by every CVM
    // converted from it, and known to whoever ran the conversion.
    sh("rm -f /etc/ssh/ssh_host_*")?;
    let unit_path = format!("/etc/systemd/system/{HOSTKEYS_UNIT_NAME}");
    g.write(&unit_path, HOSTKEYS_UNIT.as_bytes())
        .map_err(|e| anyhow!("Failed to write {}: {:?}", unit_path, e))?;
    g.mkdir_p("/etc/systemd/system/ssh.service.wants")
        .map_err(|e| anyhow!("Failed to mkdir ssh.service.wants: {:?}", e))?;
    let wants_link = format!("/etc/systemd/system/ssh.service.wants/{HOSTKEYS_UNIT_NAME}");
    sh(&format!("ln -sf '{unit_path}' '{wants_link}'"))?;

    if is_dir(g, "/etc/cloud")? {
        g.touch("/etc/cloud/cloud-init.disabled")
            .map_err(|e| anyhow!("Failed to disable cloud-init: {:?}", e))?;
        ensure_network_config(g)?;
    }

    Ok(())
}

/// Writes the DHCP fallback cloud-init would otherwise render at boot.
///
/// Cloud images ship no network configuration for the NIC: cloud-init writes
/// it on every boot (e.g. /run/systemd/network/10-cloud-init-*.network).  With
/// cloud-init disabled nothing brings the interface up, and sshd listens on a
/// guest nobody can reach.  Images that do carry their own configuration are
/// left alone.
fn ensure_network_config(g: &guestfs::Handle) -> Result<()> {
    let existing = g
        .sh("ls /etc/systemd/network/*.network /etc/netplan/*.yaml /etc/network/interfaces 2>/dev/null || true")
        .map_err(|e| anyhow!("Failed to look for network configuration: {:?}", e))?;
    if !existing.trim().is_empty() {
        return Ok(());
    }
    if !is_file(g, "/usr/lib/systemd/systemd-networkd")? {
        println!(
            "WARN: the image has no network configuration and no systemd-networkd; \
             the guest will need one to be reachable over SSH"
        );
        return Ok(());
    }

    g.mkdir_p("/etc/systemd/network")
        .map_err(|e| anyhow!("Failed to mkdir /etc/systemd/network: {:?}", e))?;
    g.write(NETWORK_CONFIG_PATH, NETWORK_CONFIG.as_bytes())
        .map_err(|e| anyhow!("Failed to write {}: {:?}", NETWORK_CONFIG_PATH, e))?;
    // Enabled on Debian cloud images, but only pulled in by netplan's
    // generator on Ubuntu; enabling offline just creates the wants/ symlink.
    g.sh("systemctl enable systemd-networkd.service")
        .map_err(|e| anyhow!("Failed to enable systemd-networkd: {:?}", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED25519: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq3 alice@laptop";

    #[test]
    fn accepts_plain_and_optioned_keys_and_drops_comments() {
        let input = format!("# team keys\n\n{ED25519}\nfrom=\"10.0.0.0/8\" {ED25519}\n");
        let out = parse_authorized_keys(&input).unwrap();
        assert_eq!(out, format!("{ED25519}\nfrom=\"10.0.0.0/8\" {ED25519}\n"));
    }

    #[test]
    fn rejects_private_keys() {
        let input = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END OPENSSH PRIVATE KEY-----\n";
        assert!(parse_authorized_keys(input).is_err());
    }

    #[test]
    fn rejects_garbage_and_empty_files() {
        assert!(parse_authorized_keys("not a key\n").is_err());
        assert!(parse_authorized_keys("ssh-ed25519\n").is_err());
        assert!(parse_authorized_keys("# only a comment\n\n").is_err());
    }

    #[test]
    fn user_names_are_restricted_to_a_shell_safe_set() {
        for ok in ["debian", "ubuntu", "_svc", "ops-1"] {
            assert!(validate_user_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "Root",
            "1abc",
            "a b",
            "a;rm -rf /",
            "$(id)",
            "root",
            &"a".repeat(33),
        ] {
            assert!(validate_user_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ssh_user_without_keys_is_an_error() {
        assert!(SshAccess::from_args(None, Some("debian".into())).is_err());
        assert!(SshAccess::from_args(None, None).unwrap().is_none());
    }
}
