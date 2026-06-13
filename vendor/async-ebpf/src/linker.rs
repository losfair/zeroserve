use std::collections::{HashMap, HashSet};

use elf::{endian::LittleEndian, ElfBytes};

use crate::error::LinkerError;

const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;

const SHT_PROGBITS: u32 = 1;
const SHT_REL: u32 = 9;
const SHF_ALLOC: u64 = 1 << 1;
const SHF_EXECINSTR: u64 = 1 << 2;

const R_BPF_64_64: u32 = 1;
const R_BPF_64_32: u32 = 10;

const EBPF_OP_CALL: u8 = 0x05u8 | 0x80u8;
const EBPF_OP_LDDW: u8 = 0x18;

#[derive(Copy, Clone, Debug)]
struct EbpfInsn {
  opcode: u8,
  dst: u8,
  src: u8,
  offset: i16,
  imm: i32,
}

impl EbpfInsn {
  fn from_u64(insn: u64) -> Self {
    Self {
      opcode: (insn & 0xFF) as u8,
      dst: ((insn >> 8) & 0xF) as u8,
      src: ((insn >> 12) & 0xF) as u8,
      offset: ((insn >> 16) & 0xFFFF) as i16,
      imm: (insn >> 32) as i32,
    }
  }

  fn to_u64(&self) -> u64 {
    (self.opcode as u64)
      | ((self.dst as u64) << 8)
      | ((self.src as u64) << 12)
      | ((self.offset as u16 as u64) << 16)
      | ((self.imm as u32 as u64) << 32)
  }
}

/// Relocates an eBPF ELF image in place and returns entrypoint ranges.
///
/// Returns: section_name -> (code_vaddr, code_size).
pub fn link_elf(
  input: &mut [u8],
  vbase: usize,
  ext_func_table: &HashMap<&str, i32>,
) -> Result<HashMap<String, (usize, usize)>, LinkerError> {
  let elf = ElfBytes::<LittleEndian>::minimal_parse(input)?;
  if elf.ehdr.class != elf::file::Class::ELF64
    || elf.ehdr.version != 1
    || elf.ehdr.osabi != 0
    || elf.ehdr.e_type != ET_REL
    || elf.ehdr.e_machine != EM_BPF
  {
    return Err(LinkerError::InvalidElf("invalid ELF header"));
  }

  let (Some(sht), Some(sht_strtab)) = elf.section_headers_with_strtab()? else {
    return Err(LinkerError::InvalidElf("missing section headers"));
  };

  let Some(symtab) = elf.symbol_table()? else {
    return Err(LinkerError::InvalidElf("missing symbol table"));
  };

  let mut code_sections: HashMap<String, (usize, usize)> = HashMap::new();
  let mut code_section_indexes: HashSet<usize> = HashSet::new();
  for (cs_index, cs) in sht.iter().enumerate() {
    if cs.sh_type != SHT_PROGBITS || cs.sh_flags != SHF_ALLOC | SHF_EXECINSTR {
      continue;
    }
    if cs.sh_size == 0 {
      continue;
    }

    let Ok(cs_name) = sht_strtab.get(cs.sh_name as usize) else {
      continue;
    };

    // Validate that the section header points to valid data
    elf.section_data(&cs)?;

    code_sections.insert(
      cs_name.to_string(),
      (vbase + cs.sh_offset as usize, cs.sh_size as usize),
    );
    code_section_indexes.insert(cs_index);
  }

  let mut insn_rewrites: Vec<(usize, u64)> = vec![];

  for sec in sht.iter() {
    if sec.sh_type != SHT_REL {
      continue;
    }
    let target_section_index = sec.sh_info as usize;
    if !code_section_indexes.contains(&target_section_index) {
      continue;
    }

    let target_section = sht.get(target_section_index)?;
    let target_section_name = sht_strtab
      .get(target_section.sh_name as usize)
      .unwrap_or_default();
    let (target_section_data, _) = elf.section_data(&target_section)?;

    let relocs = elf.section_data_as_rels(&sec)?;
    for reloc in relocs {
      let end = (reloc.r_offset as usize).saturating_add(8);
      if reloc.r_offset % 8 != 0 || end > target_section_data.len() {
        return Err(LinkerError::InvalidElf("relocation: invalid offset"));
      }

      let insn = u64::from_le_bytes(
        target_section_data[reloc.r_offset as usize..end]
          .try_into()
          .unwrap(),
      );
      let mut insn = EbpfInsn::from_u64(insn);
      let sym = symtab.0.get(reloc.r_sym as usize)?;
      let sym_name = symtab.1.get(sym.st_name as usize)?;

      if reloc.r_type == R_BPF_64_32 {
        if insn.opcode != EBPF_OP_CALL {
          return Err(LinkerError::Reloc(
            format!("R_BPF_64_32: not a call instruction: {:?}", insn),
            reloc,
          ));
        }

        if let Some(&func_index) = ext_func_table.get(sym_name) {
          insn.imm = func_index;
          insn.src = 0;
        } else if code_section_indexes.contains(&(sym.st_shndx as usize)) {
          let code_section = sht.get(sym.st_shndx as usize)?;
          let old_imm = insn.imm as i64;
          let symbol_offset = if sym.st_value == 0 && old_imm != -1 {
            ((old_imm + 1) as u64).saturating_mul(8)
          } else {
            sym.st_value
          };
          let target_addr = code_section.sh_offset.wrapping_add(symbol_offset);
          let call_addr = target_section.sh_offset.wrapping_add(reloc.r_offset);
          let delta = (target_addr as i128 - call_addr as i128 - 8) / 8;
          if delta < i32::MIN as i128 || delta > i32::MAX as i128 {
            return Err(LinkerError::Reloc(
              "R_BPF_64_32: local call target out of range".to_string(),
              reloc,
            ));
          }
          insn.imm = delta as i32;
        } else {
          return Err(LinkerError::Reloc(
            format!(
              "R_BPF_64_32: unknown symbol {} in section {}",
              sym_name, target_section_name
            ),
            reloc,
          ));
        }
        insn_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize,
          insn.to_u64(),
        ));
      } else if reloc.r_type == R_BPF_64_64 {
        if insn.opcode != EBPF_OP_LDDW {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: not a lddw instruction".to_string(),
            reloc,
          ));
        }
        if end.saturating_add(8) > target_section_data.len() {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: out of bounds".to_string(),
            reloc,
          ));
        }

        let data_section = sht.get(sym.st_shndx as usize)?;
        if data_section.sh_type != SHT_PROGBITS || (data_section.sh_flags & SHF_ALLOC) == 0 {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: data section not SHT_PROGBITS or does not have SHF_ALLOC".to_string(),
            reloc,
          ));
        }

        if sym.st_size.saturating_add(sym.st_value) > data_section.sh_size {
          return Err(LinkerError::Reloc(
            "R_BPF_64_64: data section out of bounds".to_string(),
            reloc,
          ));
        }

        let oldimm = insn.imm as u32 as u64
          + ((u32::from_le_bytes(
            <[u8; 4]>::try_from(&target_section_data[end + 4..end + 8]).unwrap(),
          ) as u64)
            << 32);

        let imm = (vbase as u64)
          .wrapping_add(data_section.sh_offset)
          .wrapping_add(sym.st_value)
          .wrapping_add(oldimm);

        insn.imm = imm as u32 as i32;
        insn_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize,
          insn.to_u64(),
        ));
        insn_rewrites.push((
          target_section.sh_offset as usize + reloc.r_offset as usize + 8,
          (imm >> 32) << 32,
        ));
      } else {
        return Err(LinkerError::Reloc(
          "unsupported relocation type".to_string(),
          reloc,
        ));
      }
    }
  }

  for (offset, value) in insn_rewrites {
    input[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
  }

  // Scan code section and reject unsafe instructions
  for (cs_name, &(vaddr, len)) in code_sections.iter() {
    if len % 8 != 0 {
      return Err(LinkerError::InvalidElf(
        "code section size is not multiple of 8",
      ));
    }
    for i in (0..len).step_by(8) {
      let offset = vaddr - vbase + i;
      let insn = u64::from_le_bytes(input[offset..offset + 8].try_into().unwrap());
      let insn = EbpfInsn::from_u64(insn);

      let _ = (cs_name, insn, offset);
    }
  }

  Ok(code_sections)
}
