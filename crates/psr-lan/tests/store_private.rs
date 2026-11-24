// SPDX-License-Identifier: AGPL-3.0-only
// The files that hold a console's keys and the service token are readable by their owner only.

use psr_lan::store;

fn temp_dir(name: &str) -> std::path::PathBuf {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).unwrap();
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    std::env::temp_dir().join(format!("ps-remote-{name}-{hex}"))
}

#[test]
fn write_private_replaces_the_file_and_its_contents() {
    let dir = temp_dir("private");
    store::create_private_dir(&dir).unwrap();
    let f = dir.join("secret");
    store::write_private(&f, b"first").unwrap();
    store::write_private(&f, b"second").unwrap();
    assert_eq!(std::fs::read(&f).unwrap(), b"second");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[cfg(unix)]
#[test]
fn on_unix_only_the_owner_can_read() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("modes");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    store::create_private_dir(&dir).unwrap();
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    let f = dir.join("secret");
    // A file left world-readable before is not kept so: it is made again.
    std::fs::write(&f, b"old").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
    store::write_private(&f, b"new").unwrap();
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    std::fs::remove_dir_all(&dir).unwrap();
}
