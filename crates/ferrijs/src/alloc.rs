//! The heap the engine runs on.
//!
//! `QuickJS` is allocation-bound: every object, shape, string and
//! property table is a separate `malloc`, and the interpreter frees and
//! re-allocates constantly because it is reference counted. The
//! platform allocator is the wrong tool for that shape (macOS's in
//! particular takes a lock per size class), so the realm points the
//! engine at mimalloc instead.
//!
//! `rquickjs`'s own [`rquickjs::allocator::RustAllocator`] would route
//! through the Rust global allocator, but it prefixes every block with
//! a size header because Rust's `dealloc` needs the layout back. That
//! is 16 bytes of overhead on allocations whose median size is a few
//! dozen, and it hides the real block size from the engine's own
//! accounting. mimalloc answers `mi_usable_size` for any pointer it
//! owns, so this implementation carries no header at all: the memory
//! limit is enforced against the size the allocator actually reserved.

use std::ffi::c_void;

use rquickjs::allocator::Allocator;

/// The engine's allocator: mimalloc, with no per-block header.
///
/// `QuickJS` requires every block to be aligned for a `u64`; mimalloc
/// guarantees at least 16-byte alignment for any size it serves, so the
/// plain (unaligned) entry points are enough.
#[derive(Debug, Clone, Copy, Default)]
pub struct MiAllocator;

// SAFETY: every method forwards to the matching mimalloc entry point.
// `alloc` / `calloc` answer a null pointer or a block of at least the
// requested size aligned to 16 (mimalloc's guarantee, which covers the
// `u64` alignment the trait demands); `dealloc` and `realloc` are only
// ever called with pointers this allocator produced, which is the
// caller's documented obligation; and `usable_size` is mimalloc's own
// answer for such a pointer.
#[allow(unsafe_code)]
unsafe impl Allocator for MiAllocator {
  fn alloc(&mut self, size: usize) -> *mut u8 {
    unsafe { libmimalloc_sys::mi_malloc(size).cast::<u8>() }
  }

  fn calloc(&mut self, count: usize, size: usize) -> *mut u8 {
    unsafe { libmimalloc_sys::mi_calloc(count, size).cast::<u8>() }
  }

  unsafe fn dealloc(&mut self, ptr: *mut u8) {
    unsafe { libmimalloc_sys::mi_free(ptr.cast::<c_void>()) }
  }

  unsafe fn realloc(&mut self, ptr: *mut u8, new_size: usize) -> *mut u8 {
    unsafe { libmimalloc_sys::mi_realloc(ptr.cast::<c_void>(), new_size).cast::<u8>() }
  }

  unsafe fn usable_size(ptr: *mut u8) -> usize {
    unsafe { libmimalloc_sys::mi_usable_size(ptr.cast::<c_void>()) }
  }
}

/// mimalloc as the process-wide Rust allocator, for a binary that wants
/// the host side of the runtime (every `String`, `Vec` and future the
/// bindings build) on the same heap as the engine.
///
/// A library must never install one of these; `ferrijs-cli` does.
///
/// ```ignore
/// #[global_allocator]
/// static GLOBAL: ferrijs::alloc::MiGlobal = ferrijs::alloc::MiGlobal;
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct MiGlobal;

// SAFETY: `GlobalAlloc`'s contract is that `alloc` answers a block of
// at least `layout.size()` bytes aligned to `layout.align()`, and that
// `dealloc` is called with the layout the block was allocated under.
// The aligned mimalloc entry points take the alignment explicitly and
// `mi_free` accepts any pointer they returned, so the layout's
// alignment is honoured on both sides.
#[allow(unsafe_code)]
unsafe impl std::alloc::GlobalAlloc for MiGlobal {
  unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
    unsafe { libmimalloc_sys::mi_malloc_aligned(layout.size(), layout.align()).cast::<u8>() }
  }

  unsafe fn alloc_zeroed(&self, layout: std::alloc::Layout) -> *mut u8 {
    unsafe { libmimalloc_sys::mi_zalloc_aligned(layout.size(), layout.align()).cast::<u8>() }
  }

  unsafe fn dealloc(&self, ptr: *mut u8, _layout: std::alloc::Layout) {
    unsafe { libmimalloc_sys::mi_free(ptr.cast::<c_void>()) }
  }

  unsafe fn realloc(&self, ptr: *mut u8, layout: std::alloc::Layout, new_size: usize) -> *mut u8 {
    unsafe { libmimalloc_sys::mi_realloc_aligned(ptr.cast::<c_void>(), new_size, layout.align()).cast::<u8>() }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn usable_size_covers_the_request() {
    let mut a = MiAllocator;
    for size in [1usize, 8, 33, 512, 4096] {
      let p = a.alloc(size);
      assert!(!p.is_null());
      #[allow(unsafe_code)]
      unsafe {
        assert!(MiAllocator::usable_size(p) >= size);
        assert_eq!(p as usize % 8, 0);
        a.dealloc(p);
      }
    }
  }

  #[test]
  fn calloc_zeroes_and_realloc_keeps_the_prefix() {
    let mut a = MiAllocator;
    let p = a.calloc(16, 4);
    assert!(!p.is_null());
    #[allow(unsafe_code)]
    unsafe {
      assert!(std::slice::from_raw_parts(p, 64).iter().all(|b| *b == 0));
      std::ptr::write_bytes(p, 0xAB, 64);
      let q = a.realloc(p, 256);
      assert!(!q.is_null());
      assert!(std::slice::from_raw_parts(q, 64).iter().all(|b| *b == 0xAB));
      a.dealloc(q);
    }
  }
}
