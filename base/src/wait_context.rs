// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

pub use event_token_derive::*;
use std::cmp::min;
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::ptr::null_mut;
use std::time::Duration;
use std::{fs::File, os::fd::FromRawFd};

use libc::{
    c_int, epoll_create1, epoll_ctl, epoll_event, epoll_wait, ENOENT, EPOLLHUP, EPOLLIN, EPOLLOUT,
    EPOLLRDHUP, EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};
use smallvec::SmallVec;

use crate::{errno_result, handle_eintr_errno, Result};

/// Trait that can be used to associate events with arbitrary enums when using
/// `WaitContext`.
///
/// Simple enums that have no or primitive variant data data can use the `#[derive(EventToken)]`
/// custom derive to implement this trait. See
/// [event_token_derive::event_token](../base_event_token_derive/fn.event_token.html) for details.
pub trait EventToken {
    /// Converts this token into a u64 that can be turned back into a token via `from_raw_token`.
    fn as_raw_token(&self) -> u64;

    /// Converts a raw token as returned from `as_raw_token` back into a token.
    ///
    /// It is invalid to give a raw token that was not returned via `as_raw_token` from the same
    /// `Self`. The implementation can expect that this will never happen as a result of its usage
    /// in `WaitContext`.
    fn from_raw_token(data: u64) -> Self;
}

impl EventToken for usize {
    fn as_raw_token(&self) -> u64 {
        *self as u64
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl EventToken for u64 {
    fn as_raw_token(&self) -> u64 {
        *self
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl EventToken for u32 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl EventToken for u16 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl EventToken for u8 {
    fn as_raw_token(&self) -> u64 {
        u64::from(*self)
    }

    fn from_raw_token(data: u64) -> Self {
        data as Self
    }
}

impl EventToken for () {
    fn as_raw_token(&self) -> u64 {
        0
    }

    fn from_raw_token(_data: u64) -> Self {}
}

/// Represents an event that has been signaled and waited for via a wait function.
#[derive(Copy, Clone, Debug)]
pub struct TriggeredEvent<T: EventToken> {
    pub token: T,
    pub is_readable: bool,
    pub is_writable: bool,
    pub is_hungup: bool,
}

/// Represents types of events to watch for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EventType {
    // Used to to temporarily stop waiting for events without
    // removing the associated descriptor from the WaitContext.
    // In most cases if a descriptor no longer needs to be
    // waited on, prefer removing it entirely with
    // WaitContext#delete
    None,
    Read,
    Write,
    ReadWrite,
}

const EVENT_CONTEXT_MAX_EVENTS: usize = 16;

impl From<EventType> for u32 {
    fn from(et: EventType) -> u32 {
        let v = match et {
            EventType::None => 0,
            EventType::Read => EPOLLIN,
            EventType::Write => EPOLLOUT,
            EventType::ReadWrite => EPOLLIN | EPOLLOUT,
        };
        v as u32
    }
}

/// Used to poll multiple objects that have file descriptors.
///
/// See [`crate::WaitContext`] for an example that uses the cross-platform wrapper.
pub struct EventContext<T> {
    epoll_ctx: File,
    // Needed to satisfy usage of T
    tokens: PhantomData<[T]>,
}

impl<T: EventToken> EventContext<T> {
    /// Creates a new `EventContext`.
    pub fn new() -> Result<EventContext<T>> {
        // SAFETY:
        // Safe because we check the return value.
        let epoll_fd = unsafe { epoll_create1(EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return errno_result();
        }
        Ok(EventContext {
            // SAFETY:
            // Safe because epoll_fd is valid.
            epoll_ctx: unsafe { File::from_raw_fd(epoll_fd) },
            tokens: PhantomData,
        })
    }

    /// Creates a new `EventContext` and adds the slice of `fd` and `token` tuples to the new
    /// context.
    ///
    /// This is equivalent to calling `new` followed by `add_many`. If there is an error, this will
    /// return the error instead of the new context.
    pub fn build_with(fd_tokens: &[(&dyn AsRawFd, T)]) -> Result<EventContext<T>> {
        let ctx = EventContext::new()?;
        ctx.add_many(fd_tokens)?;
        Ok(ctx)
    }

    /// Adds the given slice of `fd` and `token` tuples to this context.
    ///
    /// This is equivalent to calling `add` with each `fd` and `token`. If there are any errors,
    /// this method will stop adding `fd`s and return the first error, leaving this context in a
    /// undefined state.
    pub fn add_many(&self, fd_tokens: &[(&dyn AsRawFd, T)]) -> Result<()> {
        for (fd, token) in fd_tokens {
            self.add(*fd, T::from_raw_token(token.as_raw_token()))?;
        }
        Ok(())
    }

    /// Adds the given `fd` to this context and associates the given `token` with the `fd`'s
    /// readable events.
    ///
    /// A `fd` can only be added once and does not need to be kept open. If the `fd` is dropped and
    /// there were no duplicated file descriptors (i.e. adding the same descriptor with a different
    /// FD number) added to this context, events will not be reported by `wait` anymore.
    pub fn add(&self, fd: &dyn AsRawFd, token: T) -> Result<()> {
        self.add_for_event(fd, EventType::Read, token)
    }

    /// Adds the given `descriptor` to this context, watching for the specified events and
    /// associates the given 'token' with those events.
    ///
    /// A `descriptor` can only be added once and does not need to be kept open. If the `descriptor`
    /// is dropped and there were no duplicated file descriptors (i.e. adding the same descriptor
    /// with a different FD number) added to this context, events will not be reported by `wait`
    /// anymore.
    pub fn add_for_event(
        &self,
        descriptor: &dyn AsRawFd,
        event_type: EventType,
        token: T,
    ) -> Result<()> {
        let mut evt = epoll_event {
            events: event_type.into(),
            u64: token.as_raw_token(),
        };
        // SAFETY:
        // Safe because we give a valid epoll FD and FD to watch, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_fd(),
                EPOLL_CTL_ADD,
                descriptor.as_raw_fd(),
                &mut evt,
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// If `fd` was previously added to this context, the watched events will be replaced with
    /// `event_type` and the token associated with it will be replaced with the given `token`.
    pub fn modify(&self, fd: &dyn AsRawFd, event_type: EventType, token: T) -> Result<()> {
        let mut evt = epoll_event {
            events: event_type.into(),
            u64: token.as_raw_token(),
        };
        // SAFETY:
        // Safe because we give a valid epoll FD and FD to modify, as well as a valid epoll_event
        // structure. Then we check the return value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_fd(),
                EPOLL_CTL_MOD,
                fd.as_raw_fd(),
                &mut evt,
            )
        };
        if ret < 0 {
            return errno_result();
        };
        Ok(())
    }

    /// Deletes the given `fd` from this context. If the `fd` is not being polled by this context,
    /// the call is silently dropped without errors.
    ///
    /// If an `fd`'s token shows up in the list of hangup events, it should be removed using this
    /// method or by closing/dropping (if and only if the fd was never dup()'d/fork()'d) the `fd`.
    /// Failure to do so will cause the `wait` method to always return immediately, causing ~100%
    /// CPU load.
    pub fn delete(&self, fd: &dyn AsRawFd) -> Result<()> {
        // SAFETY:
        // Safe because we give a valid epoll FD and FD to stop watching. Then we check the return
        // value.
        let ret = unsafe {
            epoll_ctl(
                self.epoll_ctx.as_raw_fd(),
                EPOLL_CTL_DEL,
                fd.as_raw_fd(),
                null_mut(),
            )
        };
        // If epoll_ctl returns ENOENT it means the fd is not part of the current polling set so
        // there is nothing to delete.
        if ret < 0 && ret != ENOENT {
            return errno_result();
        };
        Ok(())
    }

    /// Waits for any events to occur in FDs that were previously added to this context.
    ///
    /// The events are level-triggered, meaning that if any events are unhandled (i.e. not reading
    /// for readable events and not closing for hungup events), subsequent calls to `wait` will
    /// return immediately. The consequence of not handling an event perpetually while calling
    /// `wait` is that the callers loop will degenerated to busy loop polling, pinning a CPU to
    /// ~100% usage.
    pub fn wait(&self) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }

    /// Like `wait` except will only block for a maximum of the given `timeout`.
    ///
    /// This may return earlier than `timeout` with zero events if the duration indicated exceeds
    /// system limits.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        let mut epoll_events: [MaybeUninit<epoll_event>; EVENT_CONTEXT_MAX_EVENTS] =
            // SAFETY:
            // `MaybeUnint<T>` has the same layout as plain `T` (`epoll_event` in our case).
            // We submit an uninitialized array to the `epoll_wait` system call, which returns how many
            // elements it initialized, and then we convert only the initialized `MaybeUnint` values
            // into `epoll_event` structures after the call.
            unsafe { MaybeUninit::uninit().assume_init() };

        let timeout_millis = if timeout.as_secs() as i64 == i64::max_value() {
            // We make the convenient assumption that 2^63 seconds is an effectively unbounded time
            // frame. This is meant to mesh with `wait` calling us with no timeout.
            -1
        } else {
            // In cases where we the number of milliseconds would overflow an i32, we substitute the
            // maximum timeout which is ~24.8 days.
            let millis = timeout
                .as_secs()
                .checked_mul(1_000)
                .and_then(|ms| ms.checked_add(u64::from(timeout.subsec_nanos()) / 1_000_000))
                .unwrap_or(i32::max_value() as u64);
            min(i32::max_value() as u64, millis) as i32
        };
        let ret = {
            let max_events = epoll_events.len() as c_int;
            // SAFETY:
            // Safe because we give an epoll context and a properly sized epoll_events array
            // pointer, which we trust the kernel to fill in properly. The `transmute` is safe,
            // since `MaybeUnint<T>` has the same layout as `T`, and the `epoll_wait` syscall will
            // initialize as many elements of the `epoll_events` array as it returns.
            unsafe {
                handle_eintr_errno!(epoll_wait(
                    self.epoll_ctx.as_raw_fd(),
                    std::mem::transmute(&mut epoll_events[0]),
                    max_events,
                    timeout_millis
                ))
            }
        };
        if ret < 0 {
            return errno_result();
        }
        let count = ret as usize;

        let events = epoll_events[0..count]
            .iter()
            .map(|e| {
                // SAFETY:
                // Converting `MaybeUninit<epoll_event>` into `epoll_event` is safe here, since we
                // are only iterating over elements that the `epoll_wait` system call initialized.
                let e = unsafe { e.assume_init() };
                TriggeredEvent {
                    token: T::from_raw_token(e.u64),
                    is_readable: e.events & (EPOLLIN as u32) != 0,
                    is_writable: e.events & (EPOLLOUT as u32) != 0,
                    is_hungup: e.events & ((EPOLLHUP | EPOLLRDHUP) as u32) != 0,
                }
            })
            .collect();
        Ok(events)
    }
}

impl<T: EventToken> AsRawFd for EventContext<T> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.epoll_ctx.as_raw_fd()
    }
}

/// Used to wait for multiple objects which are eligible for waiting.
///
/// # Example
///
/// ```
/// use base::{Event, EventToken, Result, WaitContext};
///
/// #[derive(EventToken, Copy, Clone, Debug, PartialEq, Eq)]
/// enum ExampleToken {
///    SomeEvent(u32),
///    AnotherEvent,
/// }
///
/// let evt1 = Event::new()?;
/// let evt2 = Event::new()?;
/// let another_evt = Event::new()?;
///
/// let ctx: WaitContext<ExampleToken> = WaitContext::build_with(&[
///     (&evt1, ExampleToken::SomeEvent(1)),
///     (&evt2, ExampleToken::SomeEvent(2)),
///     (&another_evt, ExampleToken::AnotherEvent),
/// ])?;
///
/// // Trigger one of the `SomeEvent` events.
/// evt2.signal()?;
///
/// // Wait for an event to fire. `wait()` will return immediately in this example because `evt2`
/// // has already been triggered, but in normal use, `wait()` will block until at least one event
/// // is signaled by another thread or process.
/// let events = ctx.wait()?;
/// let tokens: Vec<ExampleToken> = events.iter().filter(|e| e.is_readable)
///     .map(|e| e.token).collect();
/// assert_eq!(tokens, [ExampleToken::SomeEvent(2)]);
///
/// // Reset evt2 so it doesn't trigger again in the next `wait()` call.
/// let _ = evt2.reset()?;
///
/// // Trigger a different event.
/// another_evt.signal()?;
///
/// let events = ctx.wait()?;
/// let tokens: Vec<ExampleToken> = events.iter().filter(|e| e.is_readable)
///     .map(|e| e.token).collect();
/// assert_eq!(tokens, [ExampleToken::AnotherEvent]);
///
/// let _ = another_evt.reset()?;
/// # Ok::<(), base::Error>(())
/// ```
pub struct WaitContext<T: EventToken>(pub(crate) EventContext<T>);

impl<T: EventToken> WaitContext<T> {
    /// Creates a new WaitContext.
    pub fn new() -> Result<WaitContext<T>> {
        EventContext::new().map(WaitContext)
    }

    /// Creates a new WaitContext with the the associated triggers.
    pub fn build_with(triggers: &[(&dyn AsRawFd, T)]) -> Result<WaitContext<T>> {
        let ctx = WaitContext::new()?;
        ctx.add_many(triggers)?;
        Ok(ctx)
    }

    /// Adds a trigger to the WaitContext.
    pub fn add(&self, descriptor: &dyn AsRawFd, token: T) -> Result<()> {
        self.add_for_event(descriptor, EventType::Read, token)
    }

    /// Adds a trigger to the WaitContext watching for a specific type of event
    pub fn add_for_event(
        &self,
        descriptor: &dyn AsRawFd,
        event_type: EventType,
        token: T,
    ) -> Result<()> {
        self.0.add_for_event(descriptor, event_type, token)
    }

    /// Adds multiple triggers to the WaitContext.
    pub fn add_many(&self, triggers: &[(&dyn AsRawFd, T)]) -> Result<()> {
        for trigger in triggers {
            self.add(trigger.0, T::from_raw_token(trigger.1.as_raw_token()))?
        }
        Ok(())
    }

    /// Modifies a trigger already added to the WaitContext. If the descriptor is
    /// already registered, its associated token will be updated.
    pub fn modify(&self, descriptor: &dyn AsRawFd, event_type: EventType, token: T) -> Result<()> {
        self.0.modify(descriptor, event_type, token)
    }

    /// Removes the given handle from triggers registered in the WaitContext if
    /// present.
    pub fn delete(&self, descriptor: &dyn AsRawFd) -> Result<()> {
        self.0.delete(descriptor)
    }

    /// Waits for one or more of the registered triggers to become signaled.
    pub fn wait(&self) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.wait_timeout(Duration::new(i64::MAX as u64, 0))
    }

    /// Waits for one or more of the registered triggers to become signaled, failing if no triggers
    /// are signaled before the designated timeout has elapsed.
    pub fn wait_timeout(&self, timeout: Duration) -> Result<SmallVec<[TriggeredEvent<T>; 16]>> {
        self.0.wait_timeout(timeout)
    }
}

impl<T: EventToken> AsRawFd for WaitContext<T> {
    fn as_raw_fd(&self) -> std::os::unix::prelude::RawFd {
        self.0.as_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use event_token_derive::EventToken;

    use super::*;

    #[test]
    #[allow(dead_code)]
    fn event_token_derive() {
        #[derive(EventToken)]
        enum EmptyToken {}

        #[derive(PartialEq, Debug, EventToken)]
        enum Token {
            Alpha,
            Beta,
            // comments
            Gamma(u32),
            Delta { index: usize },
            Omega,
        }

        assert_eq!(
            Token::from_raw_token(Token::Alpha.as_raw_token()),
            Token::Alpha
        );
        assert_eq!(
            Token::from_raw_token(Token::Beta.as_raw_token()),
            Token::Beta
        );
        assert_eq!(
            Token::from_raw_token(Token::Gamma(55).as_raw_token()),
            Token::Gamma(55)
        );
        assert_eq!(
            Token::from_raw_token(Token::Delta { index: 100 }.as_raw_token()),
            Token::Delta { index: 100 }
        );
        assert_eq!(
            Token::from_raw_token(Token::Omega.as_raw_token()),
            Token::Omega
        );
    }
}
