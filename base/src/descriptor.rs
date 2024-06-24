use std::os::fd::{AsRawFd, RawFd};

/// A trait similar to `AsRawFds` but supports an arbitrary number of descriptors.
pub trait AsRawFds {
    fn as_raw_fds(&self) -> Vec<RawFd>;
}

impl<T> AsRawFds for T
where
    T: AsRawFd,
{
    fn as_raw_fds(&self) -> Vec<RawFd> {
        vec![self.as_raw_fd()]
    }
}
