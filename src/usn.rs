use std::path::Path;

// Read the NTFS USN via FSCTL_READ_FILE_USN_DATA. Pinning the response to
// USN_RECORD_V2 keeps the USN field at a fixed offset.
#[cfg(windows)]
pub(crate) async fn read_usn(path: &Path) -> std::io::Result<i64> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Ioctl::FSCTL_READ_FILE_USN_DATA;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new().read(true).open(&path)?;
        let handle = file.as_raw_handle();

        // READ_FILE_USN_DATA { MinMajorVersion: 2, MaxMajorVersion: 2 } —
        // V2 keeps USN at byte offset 24.
        let input: [u16; 2] = [2, 2];
        let mut output = [0u8; 4096];
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                handle as _,
                FSCTL_READ_FILE_USN_DATA,
                input.as_ptr() as *const _,
                std::mem::size_of_val(&input) as u32,
                output.as_mut_ptr() as *mut _,
                output.len() as u32,
                &mut bytes_returned,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(i64::from_le_bytes(output[24..32].try_into().unwrap()))
    })
    .await
    .expect("usn read task panicked")
}

#[cfg(not(windows))]
pub(crate) async fn read_usn(_path: &Path) -> std::io::Result<i64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "USN journal is only supported on Windows/NTFS",
    ))
}
