use nix::libc::sysconf;
use nix::libc::_SC_PAGESIZE;

mod descriptor;
mod errno;
mod event;
mod flexible_array;
mod mmap;
mod notifiers;
mod wait_context;
mod worker_thread;

#[macro_use]
pub mod handle_eintr;

use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

pub use errno::errno_result;
pub use errno::Error;
pub use errno::Result;
pub use event::Event;
pub use worker_thread::WorkerThread;

pub use wait_context::EventToken;
pub use wait_context::EventType;
pub use wait_context::TriggeredEvent;
pub use wait_context::WaitContext;

pub use notifiers::CloseNotifier;
pub use notifiers::ReadNotifier;

pub use descriptor::AsRawFds;

pub use flexible_array::vec_with_array_field;
pub use flexible_array::FlexibleArray;
pub use flexible_array::FlexibleArrayWrapper;

/// Clones `fd`, returning a new file descriptor that refers to the same open file description as
/// `fd`. The cloned fd will have the `FD_CLOEXEC` flag set but will not share any other file
/// descriptor flags with `fd`.
pub fn clone_fd(fd: &dyn AsRawFd) -> Result<RawFd> {
    // SAFETY:
    // Safe because this doesn't modify any memory and we check the return value.
    let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if ret < 0 {
        errno_result()
    } else {
        Ok(ret)
    }
}

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
pub fn pagesize() -> usize {
    // SAFETY:
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

#[macro_export]
macro_rules! syscall {
    ($e:expr) => {{
        let res = $e;
        if res < 0 {
            $crate::errno_result()
        } else {
            Ok(res)
        }
    }};
}
