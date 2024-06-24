// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use super::errno_result;
use libc::read;
use libc::write;
use libc::{c_void, eventfd, POLLIN};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;
use std::{mem, ptr};

use crate::Result;

/// Return a timespec filed with the specified Duration `duration`.
#[allow(clippy::useless_conversion)]
pub fn duration_to_timespec(duration: Duration) -> libc::timespec {
    // nsec always fits in i32 because subsec_nanos is defined to be less than one billion.
    let nsec = duration.subsec_nanos() as i32;
    libc::timespec {
        tv_sec: duration.as_secs() as libc::time_t,
        tv_nsec: nsec.into(),
    }
}

/// An inter-process event wait/notify mechanism. Loosely speaking: Writes signal the event. Reads
/// block until the event is signaled and then clear the signal.
///
/// Supports multiple simultaneous writers (i.e. signalers) but only one simultaneous reader (i.e.
/// waiter). The behavior of multiple readers is undefined in cross platform code.
///
/// Multiple `Event`s can be polled at once via `WaitContext`.
///
/// Implementation notes:
/// - Uses eventfd on Linux.
/// - Uses synchapi event objects on Windows.
/// - The `Event` and `WaitContext` APIs together cannot easily be implemented with the same
///   semantics on all platforms. In particular, it is difficult to support multiple readers, so
///   only a single reader is allowed for now. Multiple readers will result in undefined behavior.
#[derive(Debug)]
pub struct Event(pub(crate) OwnedFd);

#[derive(PartialEq, Eq, Debug)]
pub enum EventWaitResult {
    /// The `Event` was signaled.
    Signaled,
    /// Timeout limit reached.
    TimedOut,
}

impl Event {
    /// Creates new event in an unsignaled state.
    pub fn new() -> Result<Event> {
        // SAFETY:
        // This is safe because eventfd merely allocated an eventfd for our process and we handle
        // the error case.
        let ret = unsafe { eventfd(0, 0) };
        if ret < 0 {
            return errno_result();
        }

        // SAFETY:
        let owned_fd = unsafe { OwnedFd::from_raw_fd(ret) };

        Ok(Self(owned_fd))
    }

    fn write_count(&self, v: u64) -> Result<()> {
        // SAFETY:
        // This is safe because we made this fd and the pointer we pass can not overflow because we
        // give the syscall's size parameter properly.
        let ret = unsafe {
            write(
                self.as_raw_fd(),
                &v as *const u64 as *const c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret <= 0 {
            return errno_result();
        }
        Ok(())
    }

    fn read_count(&self) -> Result<u64> {
        let mut buf: u64 = 0;
        // SAFETY:
        // This is safe because we made this fd and the pointer we pass can not overflow because
        // we give the syscall's size parameter properly.
        let ret = unsafe {
            read(
                self.as_raw_fd(),
                &mut buf as *mut u64 as *mut c_void,
                mem::size_of::<u64>(),
            )
        };
        if ret <= 0 {
            return errno_result();
        }
        Ok(buf)
    }

    /// Signals the event.
    pub fn signal(&self) -> Result<()> {
        self.write_count(1)
    }

    /// Blocks until the event is signaled and clears the signal.
    ///
    /// It is undefined behavior to wait on an event from multiple threads or processes
    /// simultaneously.
    pub fn wait(&self) -> Result<()> {
        self.read_count().map(|_| ())
    }

    /// Blocks until the event is signaled and clears the signal, or until the timeout duration
    /// expires.
    ///
    /// It is undefined behavior to wait on an event from multiple threads or processes
    /// simultaneously.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<EventWaitResult> {
        let mut pfd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        };
        let timeoutspec: libc::timespec = duration_to_timespec(timeout);
        // SAFETY:
        // Safe because this only modifies |pfd| and we check the return value
        let ret = unsafe {
            libc::ppoll(
                &mut pfd as *mut libc::pollfd,
                1,
                &timeoutspec,
                ptr::null_mut(),
            )
        };
        if ret < 0 {
            return errno_result();
        }

        // no return events (revents) means we got a timeout
        if pfd.revents == 0 {
            return Ok(EventWaitResult::TimedOut);
        }

        self.wait()?;
        Ok(EventWaitResult::Signaled)
    }

    /// Clears the event without blocking.
    ///
    /// If the event is not signaled, this has no effect and returns immediately.
    pub fn reset(&self) -> Result<()> {
        // If the eventfd is currently signaled (counter > 0), `wait_timeout()` will `read()` it to
        // reset the count. Otherwise (if the eventfd is not signaled), `wait_timeout()` will return
        // immediately since we pass a zero duration. We don't care about the EventWaitResult; we
        // just want a non-blocking read to reset the counter.
        let _: EventWaitResult = self.wait_timeout(Duration::ZERO)?;
        Ok(())
    }

    /// Clones the event. The event's state is shared between cloned instances.
    ///
    /// The documented caveats for `Event` also apply to a set of cloned instances, e.g., it is
    /// undefined behavior to clone an event and then call `Event::wait` simultaneously on both
    /// objects.
    ///
    /// Implementation notes:
    ///   * Linux: The cloned instance uses a separate file descriptor.
    ///   * Windows: The cloned instance uses a separate handle.
    pub fn try_clone(&self) -> Result<Event> {
        let new_fd = self.0.try_clone()?;
        Ok(Self(new_fd))
    }
}

impl AsRawFd for Event {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
