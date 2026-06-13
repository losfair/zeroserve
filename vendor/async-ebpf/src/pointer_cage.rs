use std::ptr::NonNull;

use memmap2::{MmapOptions, MmapRaw};

use crate::error::RuntimeError;

/// Memory-mapped pointer cage with guarded stack and data regions.
pub struct PointerCage {
  region: MmapRaw,
  stack_bottom: usize,
  stack_top: usize,
  data_bottom: usize,
  data_top: usize,
  margin: usize,
}

impl PointerCage {
  /// Creates a new pointer cage with randomized guard regions.
  pub fn new(
    rng: &mut impl rand::Rng,
    stack_size: usize,
    data_size: usize,
  ) -> Result<Self, RuntimeError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size < 0 {
      return Err(RuntimeError::PlatformError("failed to get page size"));
    }
    let page_size = page_size as usize;

    assert!(page_size <= 65536 && page_size.is_power_of_two());
    assert!(stack_size % page_size == 0);

    // round up data_size to multiple of page size
    let data_size = (data_size + page_size - 1) & !(page_size - 1);

    let guard_size_1 = rng.gen_range(16..128) * page_size;
    let guard_size_2 = rng.gen_range(16..128) * page_size;
    let guard_size_3 = rng.gen_range(16..128) * page_size;

    // max range of offset in ld/st instructions
    // | margin | usable pointer cage range | margin |
    //          ^                           ^
    //      self.offset()           self.offset() + self.mask() + 1
    let margin: usize = page_size;

    let map_size = (guard_size_1 + stack_size + guard_size_2 + data_size + guard_size_3)
      .next_power_of_two()
      + margin * 2;
    let region = MmapRaw::from(
      MmapOptions::new()
        .len(map_size)
        .map_anon()
        .map_err(|_| RuntimeError::PlatformError("failed to allocate memory for pointer cage"))?,
    );
    unsafe {
      if libc::mprotect(region.as_ptr() as *mut _, map_size, libc::PROT_NONE) != 0
        || libc::mprotect(
          region.as_ptr().add(margin + guard_size_1) as *mut _,
          stack_size,
          libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
        || libc::mprotect(
          region
            .as_ptr()
            .add(margin + guard_size_1 + stack_size + guard_size_2) as *mut _,
          data_size,
          libc::PROT_READ | libc::PROT_WRITE,
        ) != 0
      {
        return Err(RuntimeError::PlatformError(
          "failed to protect memory for pointer cage",
        ));
      }
    }

    Ok(Self {
      region,
      stack_bottom: guard_size_1,
      stack_top: guard_size_1 + stack_size,
      data_bottom: guard_size_1 + stack_size + guard_size_2,
      data_top: guard_size_1 + stack_size + guard_size_2 + data_size,
      margin,
    })
  }

  /// Returns the top offset of the stack region within the cage.
  pub fn stack_top(&self) -> usize {
    self.stack_top
  }

  /// Returns the bottom offset of the stack region within the cage.
  pub fn stack_bottom(&self) -> usize {
    self.stack_bottom
  }

  /// Returns the bottom offset of the data region within the cage.
  pub fn data_bottom(&self) -> usize {
    self.data_bottom
  }

  /// Returns the pointer mask used for JIT pointer masking.
  pub fn mask(&self) -> i32 {
    let addressable_len = self.region.len() - 2 * self.margin;
    assert_eq!(addressable_len.count_ones(), 1);
    assert!(addressable_len <= 0x8000_0000usize);
    (addressable_len - 1) as i32
  }

  /// Returns the pointer offset used alongside the mask for JIT pointers.
  pub fn offset(&self) -> usize {
    self.region.as_ptr() as usize + self.margin
  }

  /// Returns the protected address range excluding the outer margins.
  pub fn protected_range_without_margins(&self) -> (usize, usize) {
    (
      self.region.as_ptr() as usize + self.margin,
      self.region.as_ptr() as usize + self.region.len() - self.margin,
    )
  }

  /// Makes the data region read-only after initialization.
  pub fn freeze_data(&self) {
    unsafe {
      if libc::mprotect(
        self.region.as_ptr().add(self.margin + self.data_bottom) as *mut _,
        self.data_top - self.data_bottom,
        libc::PROT_READ,
      ) != 0
      {
        panic!("failed to freeze data region");
      }
    }
    tracing::info!(len = self.data_top - self.data_bottom, "frozen data region");
  }

  /// Validates a stack write and returns a writable slice on success.
  pub fn safe_deref_for_write(&self, offset: usize, size: usize) -> Option<NonNull<[u8]>> {
    if size == 0 {
      return Some(NonNull::slice_from_raw_parts(NonNull::dangling(), 0));
    }

    let Some(end) = offset.checked_add(size) else {
      return None;
    };
    let ptr = if offset >= self.stack_bottom && end <= self.stack_top {
      unsafe { self.region.as_ptr().add(self.margin).add(offset) as *mut u8 }
    } else {
      return None;
    };
    unsafe {
      Some(NonNull::new_unchecked(std::ptr::slice_from_raw_parts_mut(
        ptr, size,
      )))
    }
  }

  /// Validates a stack or data read and returns a readable slice on success.
  pub fn safe_deref_for_read(&self, offset: usize, size: usize) -> Option<NonNull<[u8]>> {
    if size == 0 {
      return Some(NonNull::slice_from_raw_parts(NonNull::dangling(), 0));
    }

    let Some(end) = offset.checked_add(size) else {
      return None;
    };
    let ptr = if (offset >= self.stack_bottom && end <= self.stack_top)
      || (offset >= self.data_bottom && end <= self.data_top)
    {
      unsafe { self.region.as_ptr().add(self.margin).add(offset) as *mut u8 }
    } else {
      return None;
    };
    unsafe {
      Some(NonNull::new_unchecked(std::ptr::slice_from_raw_parts_mut(
        ptr, size,
      )))
    }
  }

  /// Returns the backing memory-mapped region.
  pub fn region(&self) -> &MmapRaw {
    &self.region
  }
}
