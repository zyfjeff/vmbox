use nix::libc;
use std::io;
use std::{os::fd::AsRawFd, ptr::null_mut};

use crate::pagesize;
use crate::Error as ErrnoError;
use log::warn;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("`add_fd_mapping` is unsupported")]
    AddFdMappingIsUnsupported,
    #[error("requested memory out of range")]
    InvalidAddress,
    #[error("requested memory range spans past the end of the region: offset={0} count={1} region_size={2}")]
    InvalidRange(usize, usize, usize),
    #[error("requested memory is not page aligned")]
    NotPageAligned,
    #[error("requested alignment is incompatible")]
    InvalidAlignment,
    #[error("mmap related system call failed: {0}")]
    SystemCallFailed(#[source] crate::Error),
    #[error("requested offset is out of range of off_t")]
    InvalidOffset,
    #[error("failed to read from file to memory: {0}")]
    ReadToMemory(#[source] io::Error),
    #[error("`remove_mapping` is unsupported")]
    RemoveMappingIsUnsupported,
    #[error("system call failed while creating the mapping: {0}")]
    StdSyscallFailed(io::Error),
    #[error("failed to write from memory to file: {0}")]
    WriteFromMemory(#[source] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Wraps an anonymous shared memory mapping in the current process. Provides
/// RAII semantics including munmap when no longer needed.
#[derive(Debug)]
pub struct MemoryMapping {
    addr: *mut u8,
    size: usize,
}

// SAFETY:
// Send and Sync aren't automatically inherited for the raw address pointer.
// Accessing that pointer is only done through the stateless interface which
// allows the object to be shared by multiple threads without a decrease in
// safety.
unsafe impl Send for MemoryMapping {}
// SAFETY: See safety comments for impl Send
unsafe impl Sync for MemoryMapping {}

impl Drop for MemoryMapping {
    fn drop(&mut self) {
        // SAFETY:
        // This is safe because we mmap the area at addr ourselves, and nobody
        // else is holding a reference to it.
        unsafe {
            libc::munmap(self.addr as *mut libc::c_void, self.size);
        }
    }
}

impl MemoryMapping {
    /// Creates an anonymous shared, read/write mapping of `size` bytes.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    pub fn new(size: usize) -> Result<MemoryMapping> {
        MemoryMapping::new_protection(size, None, libc::PROT_READ | libc::PROT_WRITE)
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    /// * `size` - Size of memory region in bytes.
    /// * `align` - Optional alignment for MemoryMapping::addr.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn new_protection(size: usize, align: Option<u64>, prot: i32) -> Result<MemoryMapping> {
        // SAFETY:
        // This is safe because we are creating an anonymous mapping in a place not already used by
        // any other area in this process.
        unsafe { MemoryMapping::try_mmap(None, size, align, prot, None) }
    }

    /// Maps the first `size` bytes of the given `fd` as read/write.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    pub fn from_fd(fd: &dyn AsRawFd, size: usize) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset(fd, size, 0)
    }

    pub fn from_fd_offset(fd: &dyn AsRawFd, size: usize, offset: u64) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection(
            fd,
            size,
            offset,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    }

    /// Maps the `size` bytes starting at `offset` bytes of the given `fd` as read/write.
    ///
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    pub fn from_fd_offset_protection(
        fd: &dyn AsRawFd,
        size: usize,
        offset: u64,
        prot: i32,
    ) -> Result<MemoryMapping> {
        MemoryMapping::from_fd_offset_protection_populate(fd, size, offset, 0, prot, false)
    }

    /// Maps `size` bytes starting at `offset` from the given `fd` as read/write, and requests
    /// that the pages are pre-populated.
    /// # Arguments
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `align` - Alignment for MemoryMapping::addr.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    /// * `populate` - Populate (prefault) page tables for a mapping.
    pub fn from_fd_offset_protection_populate(
        fd: &dyn AsRawFd,
        size: usize,
        offset: u64,
        align: u64,
        prot: i32,
        populate: bool,
    ) -> Result<MemoryMapping> {
        // SAFETY:
        // This is safe because we are creating an anonymous mapping in a place not already used
        // by any other area in this process.
        unsafe {
            MemoryMapping::try_mmap_populate(
                None,
                size,
                Some(align),
                prot,
                Some((fd, offset)),
                populate,
            )
        }
    }

    /// Creates an anonymous shared mapping of `size` bytes with `prot` protection.
    ///
    /// # Arguments
    ///
    /// * `addr` - Memory address to mmap at.
    /// * `size` - Size of memory region in bytes.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    ///
    /// # Safety
    ///
    /// This function should not be called before the caller unmaps any mmap'd regions already
    /// present at `(addr..addr+size)`.
    pub unsafe fn new_protection_fixed(
        addr: *mut u8,
        size: usize,
        prot: i32,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(Some(addr), size, None, prot, None)
    }

    /// Maps the `size` bytes starting at `offset` bytes of the given `fd` with
    /// `prot` protections.
    ///
    /// # Arguments
    ///
    /// * `addr` - Memory address to mmap at.
    /// * `fd` - File descriptor to mmap from.
    /// * `size` - Size of memory region in bytes.
    /// * `offset` - Offset in bytes from the beginning of `fd` to start the mmap.
    /// * `prot` - Protection (e.g. readable/writable) of the memory region.
    ///
    /// # Safety
    ///
    /// This function should not be called before the caller unmaps any mmap'd regions already
    /// present at `(addr..addr+size)`.
    pub unsafe fn from_descriptor_offset_protection_fixed(
        addr: *mut u8,
        fd: &dyn AsRawFd,
        size: usize,
        offset: u64,
        prot: i32,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap(Some(addr), size, None, prot, Some((fd, offset)))
    }

    /// Helper wrapper around try_mmap_populate when without MAP_POPULATE
    unsafe fn try_mmap(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: i32,
        fd: Option<(&dyn AsRawFd, u64)>,
    ) -> Result<MemoryMapping> {
        MemoryMapping::try_mmap_populate(addr, size, align, prot, fd, false)
    }

    /// Helper wrapper around libc::mmap that does some basic validation, and calls
    /// madvise with MADV_DONTDUMP on the created mmap
    unsafe fn try_mmap_populate(
        addr: Option<*mut u8>,
        size: usize,
        align: Option<u64>,
        prot: i32,
        fd: Option<(&dyn AsRawFd, u64)>,
        populate: bool,
    ) -> Result<MemoryMapping> {
        let mut flags = libc::MAP_SHARED;
        if populate {
            flags |= libc::MAP_POPULATE;
        }
        // If addr is provided, set the (FIXED | NORESERVE) flag, and validate addr alignment.
        let addr = match addr {
            Some(addr) => {
                if (addr as usize) % pagesize() != 0 {
                    return Err(Error::NotPageAligned);
                }
                flags |= libc::MAP_FIXED | libc::MAP_NORESERVE;
                addr as *mut libc::c_void
            }
            None => null_mut(),
        };

        // mmap already PAGE_SIZE align the returned address.
        let align = if align.unwrap_or(0) == pagesize() as u64 {
            Some(0)
        } else {
            align
        };

        // Add an address if an alignment is requested.
        let (addr, orig_addr, orig_size) = match align {
            None | Some(0) => (addr, None, None),
            Some(align) => {
                if !addr.is_null() || !align.is_power_of_two() {
                    return Err(Error::InvalidAlignment);
                }
                let orig_size = size + align as usize;
                let orig_addr = libc::mmap64(
                    null_mut(),
                    orig_size,
                    prot,
                    libc::MAP_PRIVATE | libc::MAP_NORESERVE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if orig_addr == libc::MAP_FAILED {
                    return Err(Error::SystemCallFailed(ErrnoError::last()));
                }

                flags |= libc::MAP_FIXED;

                let mask = align - 1;
                (
                    (orig_addr.wrapping_add(mask as usize) as u64 & !mask) as *mut libc::c_void,
                    Some(orig_addr),
                    Some(orig_size),
                )
            }
        };

        // If fd is provided, validate fd offset is within bounds. If not, it's anonymous mapping
        // and set the (ANONYMOUS | NORESERVE) flag.
        let (fd, offset) = match fd {
            Some((fd, offset)) => {
                if offset > libc::off64_t::max_value() as u64 {
                    return Err(Error::InvalidOffset);
                }
                // Map private for read-only seal. See below for upstream relax of the restriction.
                // - https://lore.kernel.org/bpf/20231013103208.kdffpyerufr4ygnw@quack3/T/
                // SAFETY:
                // Safe because no third parameter is expected and we check the return result.
                let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
                if (seals >= 0) && (seals & libc::F_SEAL_WRITE != 0) {
                    flags &= !libc::MAP_SHARED;
                    flags |= libc::MAP_PRIVATE;
                }
                (fd.as_raw_fd(), offset as libc::off64_t)
            }
            None => {
                flags |= libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
                (-1, 0)
            }
        };
        let addr = libc::mmap64(addr, size, prot, flags, fd, offset);
        if addr == libc::MAP_FAILED {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }

        // If an original mmap exists, we can now remove the unused regions
        if let Some(orig_addr) = orig_addr {
            let mut unmap_start = orig_addr as usize;
            let mut unmap_end = addr as usize;
            let mut unmap_size = unmap_end - unmap_start;

            if unmap_size > 0 {
                libc::munmap(orig_addr, unmap_size);
            }

            unmap_start = addr as usize + size;
            unmap_end = orig_addr as usize + orig_size.unwrap();
            unmap_size = unmap_end - unmap_start;

            if unmap_size > 0 {
                libc::munmap(unmap_start as *mut libc::c_void, unmap_size);
            }
        }

        // This is safe because we call madvise with a valid address and size.
        let _ = libc::madvise(addr, size, libc::MADV_DONTDUMP);

        // This is safe because KSM's only userspace visible effects are timing
        // and memory consumption; it doesn't affect rust safety semantics.
        // KSM is also disabled by default, and this flag is only a hint.
        let _ = libc::madvise(addr, size, libc::MADV_MERGEABLE);

        Ok(MemoryMapping {
            addr: addr as *mut u8,
            size,
        })
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    /// Madvise the kernel to unmap on fork.
    pub fn use_dontfork(&self) -> Result<()> {
        // SAFETY:
        // This is safe because we call madvise with a valid address and size, and we check the
        // return value.
        let ret = unsafe {
            libc::madvise(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MADV_DONTFORK,
            )
        };
        if ret == -1 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Madvise the kernel to use Huge Pages for this mapping.
    pub fn use_hugepages(&self) -> Result<()> {
        const SZ_2M: usize = 2 * 1024 * 1024;

        // THP uses 2M pages, so use THP only on mappings that are at least
        // 2M in size.
        if self.size() < SZ_2M {
            return Ok(());
        }

        // SAFETY:
        // This is safe because we call madvise with a valid address and size, and we check the
        // return value.
        let ret = unsafe {
            libc::madvise(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MADV_HUGEPAGE,
            )
        };
        if ret == -1 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Calls msync with MS_SYNC on the mapping.
    pub fn msync(&self) -> Result<()> {
        // SAFETY:
        // This is safe since we use the exact address and length of a known
        // good memory mapping.
        let ret = unsafe {
            libc::msync(
                self.as_ptr() as *mut libc::c_void,
                self.size(),
                libc::MS_SYNC,
            )
        };
        if ret == -1 {
            return Err(Error::SystemCallFailed(ErrnoError::last()));
        }
        Ok(())
    }

    /// Uses madvise to tell the kernel to remove the specified range.  Subsequent reads
    /// to the pages in the range will return zero bytes.
    pub fn remove_range(&self, mem_offset: usize, count: usize) -> Result<()> {
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY: Safe because all the args to madvise are valid and the return
        // value is checked.
        let ret = unsafe {
            // madvising away the region is the same as the guest changing it.
            // Next time it is read, it may return zero pages.
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_REMOVE,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Tell the kernel to readahead the range.
    ///
    /// This does not block the thread by I/O wait from reading the backed file. This does not
    /// guarantee that the pages are surely present unless the pages are mlock(2)ed by
    /// `lock_on_fault_unchecked()`.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn async_prefetch(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY:
        // Safe because populating the pages from the backed file does not affect the Rust memory
        // safety.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_WILLNEED,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Tell the kernel to drop the page cache.
    ///
    /// This cannot be applied to locked pages.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// NOTE: This function has destructive semantics. It throws away data in the page cache without
    /// writing it to the backing file. If the data is important, the caller should ensure it is
    /// written to disk before calling this function or should use MADV_PAGEOUT instead.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn drop_page_cache(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY:
        // Safe because dropping the page cache does not affect the Rust memory safety.
        let ret = unsafe {
            libc::madvise(
                (self.addr as usize + mem_offset) as *mut _,
                count,
                libc::MADV_DONTNEED,
            )
        };
        if ret < 0 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    /// Lock the resident pages in the range not to be swapped out.
    ///
    /// The remaining nonresident page are locked when they are populated.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn lock_on_fault(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        let addr = self.addr as usize + mem_offset;
        // SAFETY:
        // Safe because MLOCK_ONFAULT only affects the swap behavior of the kernel, so it has no
        // impact on rust semantics.
        let ret = unsafe { libc::mlock2(addr as *mut _, count, libc::MLOCK_ONFAULT) };
        if ret < 0 {
            let errno = ErrnoError::last();
            warn!(
                "failed to mlock at {:#x} with length {}: {}",
                addr as u64,
                self.size(),
                errno,
            );
            Err(Error::SystemCallFailed(errno))
        } else {
            Ok(())
        }
    }

    /// Unlock the range of pages.
    ///
    /// Unlocking non-locked pages does not fail.
    ///
    /// The `mem_offset` and `count` must be validated by caller.
    ///
    /// # Arguments
    ///
    /// * `mem_offset` - The offset of the head of the range.
    /// * `count` - The size in bytes of the range.
    pub fn unlock(&self, mem_offset: usize, count: usize) -> Result<()> {
        // Validation
        self.range_end(mem_offset, count)
            .map_err(|_| Error::InvalidRange(mem_offset, count, self.size()))?;
        // SAFETY:
        // Safe because munlock(2) does not affect the Rust memory safety.
        let ret = unsafe { libc::munlock((self.addr as usize + mem_offset) as *mut _, count) };
        if ret < 0 {
            Err(Error::SystemCallFailed(ErrnoError::last()))
        } else {
            Ok(())
        }
    }

    // Check that offset+count is valid and return the sum.
    pub(crate) fn range_end(&self, offset: usize, count: usize) -> Result<usize> {
        let mem_end = offset.checked_add(count).ok_or(Error::InvalidAddress)?;
        if mem_end > self.size() {
            return Err(Error::InvalidAddress);
        }
        Ok(mem_end)
    }
}
