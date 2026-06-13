//! arm64 JIT relocation-range tests.
//!
//! Conditional branches on arm64 carry a signed 19-bit immediate (±1 MiB
//! reach). These tests go through the raw ubpf bindings rather than
//! `ProgramLoader` because the loader's own 1 MiB code buffer rejects
//! oversized programs before the relocation logic is ever exercised.

use std::ffi::CStr;

const EBPF_OP_MOV64_IMM: u8 = 0xb7;
const EBPF_OP_CALL: u8 = 0x85;
const EBPF_OP_ATOMIC_STORE: u8 = 0xdb;
const EBPF_OP_EXIT: u8 = 0x95;

fn inst(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> [u8; 8] {
  let mut b = [0u8; 8];
  b[0] = opcode;
  b[1] = dst | (src << 4);
  b[2..4].copy_from_slice(&offset.to_le_bytes());
  b[4..8].copy_from_slice(&imm.to_le_bytes());
  b
}

unsafe extern "C" fn stub_dispatcher(
  _arg1: u64,
  _arg2: u64,
  _arg3: u64,
  _arg4: u64,
  _arg5: u64,
  _index: std::os::raw::c_uint,
  _cookie: *mut std::os::raw::c_void,
) -> u64 {
  0
}

unsafe extern "C" fn stub_validator(
  _index: std::os::raw::c_uint,
  _vm: *const crate::ubpf::ubpf_vm,
) -> bool {
  true
}

unsafe fn take_errmsg(errmsg: *mut std::os::raw::c_char) -> String {
  if errmsg.is_null() {
    return String::new();
  }
  let s = CStr::from_ptr(errmsg).to_string_lossy().into_owned();
  libc::free(errmsg as *mut _);
  s
}

#[test]
fn test_out_of_range_conditional_branch_rejected() {
  const UNWIND_HELPER_INDEX: u32 = 1;

  // A call to the unwind helper makes the JIT emit a conditional branch to
  // the exit stub, which is placed after the program body — so the branch
  // must span all of the filler below. Each atomic add expands to ~6 arm64
  // instructions, putting the exit stub well past the ±1 MiB reach.
  let mut prog: Vec<u8> = Vec::new();
  prog.extend_from_slice(&inst(EBPF_OP_CALL, 0, 0, 0, UNWIND_HELPER_INDEX as i32));
  prog.extend_from_slice(&inst(EBPF_OP_MOV64_IMM, 1, 0, 0, 0));
  prog.extend_from_slice(&inst(EBPF_OP_MOV64_IMM, 2, 0, 0, 0));
  for _ in 0..65000 {
    prog.extend_from_slice(&inst(EBPF_OP_ATOMIC_STORE, 1, 2, 0, 0));
  }
  prog.extend_from_slice(&inst(EBPF_OP_MOV64_IMM, 0, 0, 0, 0));
  prog.extend_from_slice(&inst(EBPF_OP_EXIT, 0, 0, 0, 0));

  unsafe {
    let vm = crate::ubpf::ubpf_create();
    assert!(!vm.is_null());
    assert_eq!(
      crate::ubpf::ubpf_register_external_dispatcher(
        vm,
        Some(stub_dispatcher),
        Some(stub_validator)
      ),
      0
    );
    assert_eq!(
      crate::ubpf::ubpf_set_unwind_function_index(vm, UNWIND_HELPER_INDEX),
      0
    );

    let mut errmsg = std::ptr::null_mut();
    let ret = crate::ubpf::ubpf_load(vm, prog.as_ptr() as *const _, prog.len() as u32, &mut errmsg);
    assert_eq!(ret, 0, "load failed: {}", take_errmsg(errmsg));

    let mut buf = vec![0u8; 8 << 20];
    let mut written = buf.len();
    let ret = crate::ubpf::ubpf_translate_ex(
      vm,
      buf.as_mut_ptr(),
      &mut written,
      &mut errmsg,
      crate::ubpf::JitMode_ExtendedJitMode,
    );
    assert_ne!(
      ret, 0,
      "expected translation to fail for an out-of-range conditional branch, \
       but it succeeded and emitted {written} bytes"
    );
    let msg = take_errmsg(errmsg);
    assert!(
      msg.contains("out of range"),
      "translation failed for an unexpected reason: {msg}"
    );

    crate::ubpf::ubpf_destroy(vm);
  }
}
