use core::fmt;
use std::{
    fmt::Display,
    fs::File,
    io,
    os::fd::{AsRawFd, RawFd},
    path::PathBuf,
};

use base::{errno_result, ReadNotifier, Result};
use libc::{read, STDIN_FILENO};
use thiserror::Error as ThisError;

/// Enum for possible type of serial devices
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SerialType {
    File,
    Stdout,
}

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("Unable to clone file: {0}")]
    FileClone(std::io::Error),
    #[error("Unable to create file '{1}': {0}")]
    FileCreate(std::io::Error, PathBuf),
    #[error("Unable to open file '{1}': {0}")]
    FileOpen(std::io::Error, PathBuf),
    #[error("Serial device path '{0} is invalid")]
    InvalidPath(PathBuf),
    #[error("Invalid serial hardware: {0}")]
    InvalidSerialHardware(String),
    #[error("Invalid serial type: {0}")]
    InvalidSerialType(String),
    #[error("Serial device type file requires a path")]
    PathRequired,
    #[error("Failed to connect to socket: {0}")]
    SocketConnect(std::io::Error),
    #[error("Failed to create unbound socket: {0}")]
    SocketCreate(std::io::Error),
    #[error("Unable to open system type serial: {0}")]
    SystemTypeError(std::io::Error),
}

impl Default for SerialType {
    fn default() -> Self {
        Self::Stdout
    }
}

impl Display for SerialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match &self {
            SerialType::File => "File".to_string(),
            SerialType::Stdout => "Stdout".to_string(),
        };

        write!(f, "{}", s)
    }
}

/// Serial device hardware types
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SerialHardware {
    Serial,              // Standard PC-style (8250/16550 compatible) UART
    VirtioConsole,       // virtio-console device (AsyncConsole)
    Debugcon,            // Bochs style debug port
    LegacyVirtioConsole, // legacy virtio-console device (Console)
}

impl Default for SerialHardware {
    fn default() -> Self {
        Self::Serial
    }
}

impl Display for SerialHardware {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match &self {
            SerialHardware::Serial => "serial".to_string(),
            SerialHardware::VirtioConsole => "virtio-console".to_string(),
            SerialHardware::Debugcon => "debugcon".to_string(),
            SerialHardware::LegacyVirtioConsole => "legacy-virtio-console".to_string(),
        };

        write!(f, "{}", s)
    }
}

/// Trait for types that can be used as input for a serial device.
pub trait SerialInput: io::Read + ReadNotifier + Send {}
impl SerialInput for File {}

/// # Safety
///
/// Safe only when the FD given is valid and reading the fd will have no Rust safety implications.
unsafe fn read_raw(fd: RawFd, out: &mut [u8]) -> Result<usize> {
    let ret = read(fd, out.as_mut_ptr() as *mut _, out.len());
    if ret < 0 {
        return errno_result();
    }

    Ok(ret as usize)
}

/// Read raw bytes from stdin.
///
/// This will block depending on the underlying mode of stdin. This will ignore the usual lock
/// around stdin that the stdlib usually uses. If other code is using stdin, it is undefined who
/// will get the underlying bytes.
pub fn read_raw_stdin(out: &mut [u8]) -> Result<usize> {
    // SAFETY:
    // Safe because reading from stdin shouldn't have any safety implications.
    unsafe { read_raw(STDIN_FILENO, out) }
}

// This wrapper is used in place of the libstd native version because we don't want
// buffering for stdin.
pub struct ConsoleInput(std::io::Stdin);

impl ConsoleInput {
    pub fn new() -> Self {
        Self(std::io::stdin())
    }
}

impl Default for ConsoleInput {
    fn default() -> Self {
        Self::new()
    }
}

impl io::Read for ConsoleInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        read_raw_stdin(out).map_err(|e| e.into())
    }
}

impl ReadNotifier for ConsoleInput {
    fn get_read_notifier(&self) -> &dyn AsRawFd {
        &self.0
    }
}

impl SerialInput for ConsoleInput {}
