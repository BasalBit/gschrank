//! Narrow native operations not provided by safe standard-library interfaces.

use std::{
    ffi::{CStr, CString},
    fs::File,
    io,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
    ptr,
};

const INITIAL_PASSWD_BUFFER_SIZE: usize = 16 * 1024;
const MAX_PASSWD_BUFFER_SIZE: usize = 1024 * 1024;

pub(super) fn effective_user_id() -> u32 {
    // SAFETY: `geteuid` has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

pub(super) fn home_directory() -> io::Result<PathBuf> {
    // SAFETY: `sysconf` has no pointer arguments. A negative return means the
    // implementation supplied no fixed maximum, so the bounded default is used.
    let configured_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buffer_size = usize::try_from(configured_size)
        .unwrap_or(INITIAL_PASSWD_BUFFER_SIZE)
        .clamp(INITIAL_PASSWD_BUFFER_SIZE, MAX_PASSWD_BUFFER_SIZE);

    loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = ptr::null_mut();
        let mut buffer = vec![0_u8; buffer_size];
        // SAFETY: `record` points to writable storage; `buffer` remains live and
        // writable for the call; `result` is a valid output pointer. The record's
        // string pointers are used only before `buffer` is dropped.
        let status = unsafe {
            libc::getpwuid_r(
                effective_user_id(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &raw mut result,
            )
        };
        if status == libc::ERANGE && buffer_size < MAX_PASSWD_BUFFER_SIZE {
            buffer_size = buffer_size.saturating_mul(2).min(MAX_PASSWD_BUFFER_SIZE);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "current user record not found",
            ));
        }
        // SAFETY: successful `getpwuid_r` initialized `record`; `pw_dir` points
        // into the still-live buffer and is required to be NUL-terminated.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "current user record has no home directory",
            ));
        }
        // SAFETY: `pw_dir` is non-null and NUL-terminated by `getpwuid_r`; the
        // bytes are copied into an owned path before its backing buffer is dropped.
        let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
        return Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)));
    }
}

pub(super) fn full_sync(file: &File) -> io::Result<()> {
    // SAFETY: the descriptor comes from a live `File`; `F_FULLFSYNC` takes no
    // additional variadic argument and does not retain the descriptor.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn is_apfs(path: &Path) -> io::Result<bool> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `path` is NUL-terminated and valid for the duration of the call;
    // `stats` points to writable storage for one `statfs` value.
    let result = unsafe { libc::statfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful `statfs` call initialized the complete structure.
    let stats = unsafe { stats.assume_init() };
    let bytes = stats
        .f_fstypename
        .iter()
        .map(|byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .take_while(|byte| *byte != 0)
        .collect::<Vec<_>>();
    Ok(bytes == b"apfs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_an_absolute_home_from_the_native_user_record() {
        let home = home_directory().unwrap();
        assert!(home.is_absolute());
        assert!(home.components().count() > 1);
    }
}
