//! Secret-file input for the daemon: passphrases and restore mnemonics
//! arrive by file (or, discouraged, by environment variable — see the
//! `kultd` usage text). Files are refused unless they are private to the
//! owner, so a misconfigured deployment fails loudly instead of leaking
//! quietly.

use std::path::Path;

/// Read a secret file, refusing group- or world-accessible permissions
/// (anything beyond `chmod 600`). The check runs on the opened file itself,
/// not the path, so it cannot be raced against a swap. On non-Unix targets
/// there is no mode to check and the file is read as-is.
pub fn read_secret_file(path: &Path, what: &str) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| format!("{what}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = file
            .metadata()
            .map_err(|e| format!("{what}: {e}"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{what}: {} is group- or world-accessible (mode {:03o}); chmod 600 it",
                path.display(),
                mode & 0o777
            ));
        }
    }
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)
        .map_err(|e| format!("{what}: {e}"))?;
    Ok(raw)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_secret(dir: &Path, mode: u32) -> std::path::PathBuf {
        let path = dir.join("secret");
        std::fs::write(&path, b"hunter2\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn owner_only_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret(dir.path(), 0o600);
        assert_eq!(read_secret_file(&path, "test").unwrap(), b"hunter2\n");
    }

    #[test]
    fn group_readable_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret(dir.path(), 0o640);
        let err = read_secret_file(&path, "test").unwrap_err();
        assert!(err.contains("chmod 600"), "unexpected error: {err}");
    }

    #[test]
    fn world_readable_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_secret(dir.path(), 0o644);
        assert!(read_secret_file(&path, "test").is_err());
    }

    #[test]
    fn missing_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_secret_file(&dir.path().join("absent"), "test").is_err());
    }
}
