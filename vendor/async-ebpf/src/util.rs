use std::ptr::NonNull;

/// Returns true if two non-null byte slices overlap in memory.
pub fn nonnull_bytes_overlap(a: NonNull<[u8]>, b: NonNull<[u8]>) -> bool {
  let a_start = a.as_ptr() as *const u8 as usize;
  let b_start = b.as_ptr() as *const u8 as usize;
  let a_end = a_start + a.len();
  let b_end = b_start + b.len();

  a_start < b_end && b_start < a_end
}
