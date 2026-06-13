use std::{
    collections::HashSet,
    ffi::{CStr, CString, OsStr, c_char, c_int, c_void},
    fs,
    os::unix::ffi::OsStrExt,
    path::Path,
    ptr::NonNull,
};

use anyhow::{Context, Result, anyhow, bail};

const TCC_OUTPUT_OBJ: c_int = 3;
const TCC_OPTIONS: &str = "-Wall -mcpu=v3 -fno-builtin";

#[repr(C)]
struct TccState {
    _private: [u8; 0],
}

type TccErrorFunc = unsafe extern "C" fn(*mut c_void, *const c_char);

unsafe extern "C" {
    fn tcc_new() -> *mut TccState;
    fn tcc_delete(state: *mut TccState);
    fn tcc_set_error_func(
        state: *mut TccState,
        error_opaque: *mut c_void,
        error_func: Option<TccErrorFunc>,
    );
    fn tcc_set_options(state: *mut TccState, options: *const c_char) -> c_int;
    fn tcc_add_include_path(state: *mut TccState, path: *const c_char) -> c_int;
    fn tcc_set_output_type(state: *mut TccState, output_type: c_int) -> c_int;
    fn tcc_add_file(state: *mut TccState, filename: *const c_char) -> c_int;
    fn tcc_compile_string(state: *mut TccState, source: *const c_char) -> c_int;
    fn tcc_output_file(state: *mut TccState, filename: *const c_char) -> c_int;
}

pub fn compile_file_to_object(source: &Path, include_dir: &Path, output: &Path) -> Result<()> {
    let mut compiler = Compiler::new()?;
    compiler.add_include_path(include_dir)?;
    compiler.compile_file(source)?;
    compiler.output_file(output)?;
    fold_text_subprograms(output)?;
    ensure_nonempty_object(output)
}

pub fn compile_source_to_object(
    source: &str,
    source_name: &str,
    include_dir: &Path,
    output: &Path,
) -> Result<()> {
    let mut compiler = Compiler::new()?;
    compiler.add_include_path(include_dir)?;
    compiler.compile_source(source, source_name)?;
    compiler.output_file(output)?;
    fold_text_subprograms(output)?;
    ensure_nonempty_object(output)
}

struct Compiler {
    state: NonNull<TccState>,
    diagnostics: Box<Vec<String>>,
}

impl Compiler {
    fn new() -> Result<Self> {
        let state = NonNull::new(unsafe { tcc_new() })
            .ok_or_else(|| anyhow!("failed to create tinycc compiler"))?;
        let mut compiler = Self {
            state,
            diagnostics: Box::new(Vec::new()),
        };
        unsafe {
            tcc_set_error_func(
                compiler.state.as_ptr(),
                compiler.diagnostics.as_mut() as *mut Vec<String> as *mut c_void,
                Some(collect_diagnostic),
            );
        }
        compiler.check("failed to configure tinycc options", unsafe {
            tcc_set_options(compiler.state.as_ptr(), c_string(TCC_OPTIONS)?.as_ptr())
        })?;
        compiler.check("failed to set tinycc output type", unsafe {
            tcc_set_output_type(compiler.state.as_ptr(), TCC_OUTPUT_OBJ)
        })?;
        Ok(compiler)
    }

    fn add_include_path(&mut self, path: &Path) -> Result<()> {
        let c_path = path_to_cstring(path)?;
        self.check(
            &format!("failed to add include path {}", path.display()),
            unsafe { tcc_add_include_path(self.state.as_ptr(), c_path.as_ptr()) },
        )
    }

    fn compile_file(&mut self, source: &Path) -> Result<()> {
        let c_source = path_to_cstring(source)?;
        self.check(&format!("tinycc failed for {}", source.display()), unsafe {
            tcc_add_file(self.state.as_ptr(), c_source.as_ptr())
        })
    }

    fn compile_source(&mut self, source: &str, source_name: &str) -> Result<()> {
        let labelled = format!("#line 1 \"{}\"\n{}", escape_c_string(source_name), source);
        let c_source = c_string(&labelled)?;
        self.check(
            "tinycc failed to compile the generated middleware",
            unsafe { tcc_compile_string(self.state.as_ptr(), c_source.as_ptr()) },
        )
    }

    fn output_file(&mut self, output: &Path) -> Result<()> {
        let c_output = path_to_cstring(output)?;
        self.check(
            &format!("tinycc failed to write {}", output.display()),
            unsafe { tcc_output_file(self.state.as_ptr(), c_output.as_ptr()) },
        )
    }

    fn check(&self, context: &str, code: c_int) -> Result<()> {
        if code == 0 {
            return Ok(());
        }
        let diagnostics = self.diagnostics.join("\n");
        if diagnostics.is_empty() {
            bail!("{context}");
        }
        bail!("{context}:\n{diagnostics}");
    }
}

impl Drop for Compiler {
    fn drop(&mut self) {
        unsafe {
            tcc_delete(self.state.as_ptr());
        }
    }
}

unsafe extern "C" fn collect_diagnostic(opaque: *mut c_void, msg: *const c_char) {
    if opaque.is_null() || msg.is_null() {
        return;
    }
    let diagnostics = unsafe { &mut *(opaque as *mut Vec<String>) };
    let msg = unsafe { CStr::from_ptr(msg) }
        .to_string_lossy()
        .into_owned();
    diagnostics.push(msg);
}

fn ensure_nonempty_object(path: &Path) -> Result<()> {
    let metadata =
        fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() == 0 {
        bail!("tinycc produced an empty object at {}", path.display());
    }
    Ok(())
}

fn fold_text_subprograms(path: &Path) -> Result<()> {
    let input = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let Some(output) = fold_text_subprograms_bytes(&input)
        .with_context(|| format!("failed to rewrite {}", path.display()))?
    else {
        return Ok(());
    };
    fs::write(path, output).with_context(|| format!("failed to rewrite {}", path.display()))
}

const SHT_SYMTAB: u32 = 2;
const SHT_PROGBITS: u32 = 1;
const SHT_REL: u32 = 9;
const SHF_ALLOC_EXEC: u64 = 0x6;
const EBPF_OP_CALL: u8 = 0x85;
const R_BPF_64_32: u32 = 10;

#[derive(Clone)]
struct ElfSection {
    name: String,
    name_offset: u32,
    sh_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
    data: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ElfSymbol {
    name_offset: u32,
    shndx: u16,
    value: u64,
}

#[derive(Clone, Copy)]
struct ElfRel {
    offset: u64,
    info: u64,
}

impl ElfRel {
    fn sym(self) -> usize {
        (self.info >> 32) as usize
    }

    fn typ(self) -> u32 {
        self.info as u32
    }
}

fn fold_text_subprograms_bytes(input: &[u8]) -> Result<Option<Vec<u8>>> {
    if input.len() < 64
        || &input[0..4] != b"\x7fELF"
        || input[4] != 2
        || input[5] != 1
        || read_u16(input, 18)? != 247
    {
        return Ok(None);
    }

    let shoff = read_u64(input, 40)? as usize;
    let shentsize = read_u16(input, 58)? as usize;
    let shnum = read_u16(input, 60)? as usize;
    let shstrndx = read_u16(input, 62)? as usize;
    if shentsize != 64 || shnum == 0 || shstrndx >= shnum {
        return Ok(None);
    }

    let mut sections = parse_sections(input, shoff, shnum)?;
    let shstr = section_data(input, &sections[shstrndx])?;
    for section in &mut sections {
        section.name = read_cstr(shstr, section.name_offset as usize).unwrap_or_default();
    }

    let Some(text_idx) = sections
        .iter()
        .position(|s| s.name == ".text" && s.sh_type == SHT_PROGBITS && s.flags == SHF_ALLOC_EXEC)
    else {
        return Ok(None);
    };
    let text_data = sections[text_idx].data.clone();
    if text_data.is_empty() || text_data.len() % 8 != 0 {
        return Ok(None);
    }

    let Some(symtab_idx) = sections.iter().position(|s| s.sh_type == SHT_SYMTAB) else {
        return Ok(None);
    };
    let strtab_idx = sections[symtab_idx].link as usize;
    if strtab_idx >= sections.len() {
        return Ok(None);
    }
    let symbols = parse_symbols(&sections[symtab_idx])?;
    let strtab = sections[strtab_idx].data.clone();

    let text_relocs = relocs_for(&sections, text_idx)?;
    let mut changed = false;
    let code_targets: Vec<usize> = sections
        .iter()
        .enumerate()
        .filter_map(|(idx, s)| {
            (idx != text_idx
                && s.sh_type == SHT_PROGBITS
                && s.flags == SHF_ALLOC_EXEC
                && s.name.starts_with("zeroserve."))
            .then_some(idx)
        })
        .collect();

    for target_idx in code_targets {
        let rel_idx = sections
            .iter()
            .position(|s| s.sh_type == SHT_REL && s.info as usize == target_idx);
        let Some(rel_idx) = rel_idx else {
            continue;
        };
        let relocs = parse_rels(&sections[rel_idx])?;
        let has_text_calls = relocs
            .iter()
            .any(|rel| is_text_call_reloc(*rel, &symbols, &strtab, text_idx));
        if !has_text_calls {
            let pruned_relocs = prune_invalid_call_relocs(&sections[target_idx].data, relocs)?;
            let pruned_data = encode_rels(&pruned_relocs);
            if pruned_data != sections[rel_idx].data {
                sections[rel_idx].data = pruned_data;
                sections[rel_idx].size = sections[rel_idx].data.len() as u64;
                changed = true;
            }
            continue;
        }

        let original_len = sections[target_idx].data.len();
        if original_len % 8 != 0 {
            continue;
        }
        let mut target_data = sections[target_idx].data.clone();
        target_data.extend_from_slice(&text_data);

        let mut kept_relocs = Vec::new();
        for rel in relocs {
            if is_text_call_reloc(rel, &symbols, &strtab, text_idx) {
                rewrite_local_call(&mut target_data, rel, &symbols, original_len, text_idx)?;
            } else {
                kept_relocs.push(rel);
            }
        }
        for rel in &text_relocs {
            let mut copied = *rel;
            copied.offset = copied
                .offset
                .checked_add(original_len as u64)
                .ok_or_else(|| anyhow!("relocation offset overflow"))?;
            if is_text_call_reloc(copied, &symbols, &strtab, text_idx) {
                rewrite_local_call(&mut target_data, copied, &symbols, original_len, text_idx)?;
            } else {
                kept_relocs.push(copied);
            }
        }
        kept_relocs = prune_invalid_call_relocs(&target_data, kept_relocs)?;

        sections[target_idx].data = target_data;
        sections[target_idx].size = sections[target_idx].data.len() as u64;
        sections[rel_idx].data = encode_rels(&kept_relocs);
        sections[rel_idx].size = sections[rel_idx].data.len() as u64;
        changed = true;
    }

    if !changed {
        return Ok(None);
    }
    rebuild_elf(input, &mut sections).map(Some)
}

fn parse_sections(input: &[u8], shoff: usize, shnum: usize) -> Result<Vec<ElfSection>> {
    let mut sections = Vec::with_capacity(shnum);
    for idx in 0..shnum {
        let off = shoff
            .checked_add(idx * 64)
            .ok_or_else(|| anyhow!("section header offset overflow"))?;
        if off + 64 > input.len() {
            bail!("section header out of bounds");
        }
        let mut section = ElfSection {
            name: String::new(),
            name_offset: read_u32(input, off)?,
            sh_type: read_u32(input, off + 4)?,
            flags: read_u64(input, off + 8)?,
            addr: read_u64(input, off + 16)?,
            offset: read_u64(input, off + 24)?,
            size: read_u64(input, off + 32)?,
            link: read_u32(input, off + 40)?,
            info: read_u32(input, off + 44)?,
            addralign: read_u64(input, off + 48)?,
            entsize: read_u64(input, off + 56)?,
            data: Vec::new(),
        };
        section.data = section_data(input, &section)?.to_vec();
        sections.push(section);
    }
    Ok(sections)
}

fn section_data<'a>(input: &'a [u8], section: &ElfSection) -> Result<&'a [u8]> {
    if section.sh_type == 8 || section.size == 0 {
        return Ok(&[]);
    }
    let start = section.offset as usize;
    let end = start
        .checked_add(section.size as usize)
        .ok_or_else(|| anyhow!("section data overflow"))?;
    input
        .get(start..end)
        .ok_or_else(|| anyhow!("section data out of bounds"))
}

fn parse_symbols(symtab: &ElfSection) -> Result<Vec<ElfSymbol>> {
    let entsize = if symtab.entsize == 0 {
        24
    } else {
        symtab.entsize as usize
    };
    if entsize < 24 {
        bail!("invalid symbol entry size");
    }
    let mut out = Vec::new();
    for chunk in symtab.data.chunks_exact(entsize) {
        out.push(ElfSymbol {
            name_offset: read_u32(chunk, 0)?,
            shndx: read_u16(chunk, 6)?,
            value: read_u64(chunk, 8)?,
        });
    }
    Ok(out)
}

fn relocs_for(sections: &[ElfSection], target_idx: usize) -> Result<Vec<ElfRel>> {
    if let Some(rel_sec) = sections
        .iter()
        .find(|s| s.sh_type == SHT_REL && s.info as usize == target_idx)
    {
        parse_rels(rel_sec)
    } else {
        Ok(Vec::new())
    }
}

fn parse_rels(section: &ElfSection) -> Result<Vec<ElfRel>> {
    let entsize = if section.entsize == 0 {
        16
    } else {
        section.entsize as usize
    };
    if entsize < 16 {
        bail!("invalid relocation entry size");
    }
    let mut out = Vec::new();
    for chunk in section.data.chunks_exact(entsize) {
        out.push(ElfRel {
            offset: read_u64(chunk, 0)?,
            info: read_u64(chunk, 8)?,
        });
    }
    Ok(out)
}

fn prune_invalid_call_relocs(section_data: &[u8], relocs: Vec<ElfRel>) -> Result<Vec<ElfRel>> {
    let mut out = Vec::with_capacity(relocs.len());
    let mut call_offsets = HashSet::new();

    for rel in relocs {
        if rel.typ() == R_BPF_64_32 {
            let offset = rel.offset as usize;
            if offset + 8 > section_data.len() || offset % 8 != 0 {
                bail!("invalid call relocation offset");
            }
            if section_data[offset] != EBPF_OP_CALL {
                continue;
            }
            if !call_offsets.insert(rel.offset) {
                continue;
            }
        }
        out.push(rel);
    }

    Ok(out)
}

fn is_text_call_reloc(rel: ElfRel, symbols: &[ElfSymbol], strtab: &[u8], text_idx: usize) -> bool {
    if rel.typ() != R_BPF_64_32 {
        return false;
    }
    let Some(sym) = symbols.get(rel.sym()) else {
        return false;
    };
    if sym.shndx as usize == text_idx {
        return true;
    }
    read_cstr(strtab, sym.name_offset as usize).as_deref() == Some(".text")
}

fn rewrite_local_call(
    target_data: &mut [u8],
    rel: ElfRel,
    symbols: &[ElfSymbol],
    original_len: usize,
    text_idx: usize,
) -> Result<()> {
    let call_offset = rel.offset as usize;
    if call_offset + 8 > target_data.len() || call_offset % 8 != 0 {
        bail!("invalid local call relocation offset");
    }
    if target_data[call_offset] != EBPF_OP_CALL {
        return Ok(());
    }
    let sym = symbols
        .get(rel.sym())
        .ok_or_else(|| anyhow!("local call relocation has invalid symbol"))?;
    let old_imm = read_i32(target_data, call_offset + 4)? as i64;
    let text_insn = if sym.shndx as usize == text_idx && sym.value != 0 {
        (sym.value / 8) as i64
    } else {
        old_imm + 1
    };
    let target_insn = (original_len / 8) as i64 + text_insn;
    let call_insn = (call_offset / 8) as i64;
    let new_imm = target_insn - call_insn - 1;
    if new_imm < i32::MIN as i64 || new_imm > i32::MAX as i64 {
        bail!("local call target out of range");
    }
    target_data[call_offset + 1] = (target_data[call_offset + 1] & 0x0f) | 0x10;
    target_data[call_offset + 4..call_offset + 8].copy_from_slice(&(new_imm as i32).to_le_bytes());
    Ok(())
}

fn encode_rels(rels: &[ElfRel]) -> Vec<u8> {
    let mut out = Vec::with_capacity(rels.len() * 16);
    for rel in rels {
        out.extend_from_slice(&rel.offset.to_le_bytes());
        out.extend_from_slice(&rel.info.to_le_bytes());
    }
    out
}

fn rebuild_elf(input: &[u8], sections: &mut [ElfSection]) -> Result<Vec<u8>> {
    let mut out = input[..64].to_vec();
    for (idx, section) in sections.iter_mut().enumerate() {
        if idx == 0 {
            section.offset = 0;
            section.size = 0;
            continue;
        }
        if section.sh_type == 8 {
            section.offset = out.len() as u64;
            section.size = section.data.len() as u64;
            continue;
        }
        align_vec(&mut out, section.addralign.max(1) as usize);
        section.offset = out.len() as u64;
        section.size = section.data.len() as u64;
        out.extend_from_slice(&section.data);
    }

    align_vec(&mut out, 8);
    let shoff = out.len() as u64;
    for section in sections {
        out.extend_from_slice(&section.name_offset.to_le_bytes());
        out.extend_from_slice(&section.sh_type.to_le_bytes());
        out.extend_from_slice(&section.flags.to_le_bytes());
        out.extend_from_slice(&section.addr.to_le_bytes());
        out.extend_from_slice(&section.offset.to_le_bytes());
        out.extend_from_slice(&section.size.to_le_bytes());
        out.extend_from_slice(&section.link.to_le_bytes());
        out.extend_from_slice(&section.info.to_le_bytes());
        out.extend_from_slice(&section.addralign.to_le_bytes());
        out.extend_from_slice(&section.entsize.to_le_bytes());
    }
    out[40..48].copy_from_slice(&shoff.to_le_bytes());
    Ok(out)
}

fn align_vec(out: &mut Vec<u8>, align: usize) {
    if align <= 1 {
        return;
    }
    let rem = out.len() % align;
    if rem != 0 {
        out.resize(out.len() + align - rem, 0);
    }
}

fn read_cstr(data: &[u8], offset: usize) -> Option<String> {
    let rest = data.get(offset..)?;
    let len = rest.iter().position(|b| *b == 0)?;
    std::str::from_utf8(&rest[..len])
        .ok()
        .map(ToOwned::to_owned)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        data.get(offset..offset + 2)
            .ok_or_else(|| anyhow!("u16 read out of bounds"))?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        data.get(offset..offset + 4)
            .ok_or_else(|| anyhow!("u32 read out of bounds"))?
            .try_into()
            .unwrap(),
    ))
}

fn read_i32(data: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_le_bytes(
        data.get(offset..offset + 4)
            .ok_or_else(|| anyhow!("i32 read out of bounds"))?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        data.get(offset..offset + 8)
            .ok_or_else(|| anyhow!("u64 read out of bounds"))?
            .try_into()
            .unwrap(),
    ))
}

fn path_to_cstring(path: &Path) -> Result<CString> {
    os_str_to_cstring(path.as_os_str())
        .with_context(|| format!("path contains an interior NUL: {}", path.display()))
}

fn os_str_to_cstring(value: &OsStr) -> Result<CString> {
    CString::new(value.as_bytes()).map_err(Into::into)
}

fn c_string(value: &str) -> Result<CString> {
    CString::new(value).context("C source contains an interior NUL")
}

fn escape_c_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
