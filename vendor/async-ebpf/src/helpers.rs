use crate::program::{HelperScope, MutableUserMemory};

/// Function signature for eBPF helpers invoked by the runtime.
pub type Helper =
  fn(scope: &HelperScope, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> Result<u64, ()>;

/// Writes a NUL-terminated C string assembled from slices into user memory.
///
/// Return value has the same semantics as `snprintf`.
pub fn write_cstr(mut input: &[&[u8]], output: &mut MutableUserMemory) -> u64 {
  let input_len = input.iter().map(|x| x.len()).sum::<usize>();

  if output.len() == 0 {
    return input_len as u64;
  }

  let copy_len = input_len.min(output.len() - 1);
  let mut written_len = 0;

  while written_len < copy_len {
    let part = input[0];
    input = &input[1..];
    let part_copy_len = part.len().min(copy_len - written_len);
    output[written_len..written_len + part_copy_len].copy_from_slice(&part[..part_copy_len]);
    written_len += part_copy_len;
  }

  output[copy_len] = 0;
  input_len as u64
}
