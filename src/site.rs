use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::File as StdFile,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use tar::{Archive, EntryType};

use crate::bpf_compiler::EbpfCompiler;
use crate::ratelimit::RateLimitManager;

pub struct Site {
    pub tar_file: StdFile,
    pub entries: HashMap<String, Arc<TarEntry>>,
    pub directories: HashSet<String>,
    pub directory_mtimes: HashMap<String, u64>,
    pub total_bytes: u64,
    pub total_entries: usize,
    pub rate_limit_manager: Arc<RateLimitManager>,
}

#[derive(Debug)]
pub struct TarEntry {
    pub path: String,
    pub offset: u64,
    pub size: u64,
    pub etag: String,
    pub mtime: u64,
}

impl Site {
    pub fn load_path(
        path: &Path,
        max_rate_limit_buckets: usize,
        compiler: EbpfCompiler,
    ) -> Result<Self> {
        if is_standalone_script_path(path) {
            Self::load_standalone_script(path, max_rate_limit_buckets, compiler)
        } else {
            Self::load(path, max_rate_limit_buckets)
        }
    }

    pub fn load(path: &Path, max_rate_limit_buckets: usize) -> Result<Self> {
        let file = StdFile::open(path)
            .with_context(|| format!("failed to open tarball {}", path.display()))?;
        Self::load_from_file(file, max_rate_limit_buckets)
            .with_context(|| format!("failed to load tarball {}", path.display()))
    }

    /// Load a site from an already-open tarball file (e.g. an in-memory
    /// `memfd`). The file must support positional reads for the lifetime of the
    /// `Site`, exactly like an on-disk tarball.
    pub fn load_from_file(file: StdFile, max_rate_limit_buckets: usize) -> Result<Self> {
        let meta = file.metadata().context("stat failed for tarball file")?;
        let mut archive = Archive::new(file);
        let mut entries = HashMap::new();
        let mut directories = HashSet::new();
        let mut directory_mtimes = HashMap::new();

        let iter = archive
            .entries()
            .context("failed to iterate over tarball entries")?;
        for entry_res in iter {
            let mut entry = entry_res.context("unable to decode tar entry")?;
            let entry_type = entry.header().entry_type();
            let raw_path = entry.path().context("invalid tar entry path")?;
            let normalized = normalize_tar_path(raw_path.to_string_lossy().as_ref());
            if normalized.is_empty() {
                continue;
            }
            match entry_type {
                EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => {
                    let offset = entry.raw_file_position();
                    let size = entry.size();
                    let etag = compute_entry_etag(&mut entry)
                        .with_context(|| format!("failed to hash tar entry {}", normalized))?;
                    let mtime = entry.header().mtime().unwrap_or(0);
                    let arc_entry = Arc::new(TarEntry {
                        path: normalized.clone(),
                        offset,
                        size,
                        etag,
                        mtime,
                    });
                    entries.insert(normalized.clone(), arc_entry);
                    mark_parents(&normalized, &mut directories);
                }
                EntryType::Directory => {
                    let mtime = entry.header().mtime().unwrap_or(0);
                    directories.insert(normalized.clone());
                    directory_mtimes.insert(normalized.clone(), mtime);
                    mark_parents(&normalized, &mut directories);
                }
                _ => {}
            }
        }

        if entries.is_empty() {
            bail!("tarball does not contain any regular files");
        }

        let total_entries = entries.len();
        Ok(Self {
            tar_file: archive.into_inner(),
            entries,
            directories,
            directory_mtimes,
            total_bytes: meta.len(),
            total_entries,
            rate_limit_manager: Arc::new(RateLimitManager::new(max_rate_limit_buckets)),
        })
    }

    pub fn load_from_bytes(
        name: &str,
        bytes: &[u8],
        max_rate_limit_buckets: usize,
    ) -> Result<Self> {
        let file = memfd_from_bytes(name, bytes)?;
        Self::load_from_file(file, max_rate_limit_buckets)
    }

    pub fn load_standalone_script(
        path: &Path,
        max_rate_limit_buckets: usize,
        compiler: EbpfCompiler,
    ) -> Result<Self> {
        let script_name = standalone_script_name(path)?;
        let object = if is_script_c_path(path) {
            crate::script_compile::compile_c_path_to_object_bytes(path, compiler)
                .with_context(|| format!("failed to compile script {}", path.display()))?
        } else {
            std::fs::read(path)
                .with_context(|| format!("failed to read script object {}", path.display()))?
        };
        if object.is_empty() {
            bail!("script {} produced an empty object", path.display());
        }
        let tarball = script_object_tarball(&script_name, &object).with_context(|| {
            format!(
                "failed to build in-memory script site for {}",
                path.display()
            )
        })?;
        Self::load_from_bytes(
            "zeroserve-standalone-script",
            &tarball,
            max_rate_limit_buckets,
        )
        .with_context(|| format!("failed to load standalone script {}", path.display()))
    }

    pub fn load_directory(
        path: &Path,
        max_rate_limit_buckets: usize,
        compiler: EbpfCompiler,
    ) -> Result<Self> {
        let tarball = crate::pack::pack_site_to_vec(path, compiler)
            .with_context(|| format!("failed to pack directory {}", path.display()))?;
        Self::load_from_bytes("zeroserve-directory-site", &tarball, max_rate_limit_buckets)
            .with_context(|| format!("failed to load directory {}", path.display()))
    }

    fn get_entry_safe<'a>(&'a self, key: &str) -> Option<&'a Arc<TarEntry>> {
        if key.starts_with(".zeroserve/") {
            return None;
        }
        self.entries.get(key)
    }

    pub fn lookup(
        &self,
        path: &NormalizedPath,
        default_index: &str,
        try_html: bool,
    ) -> Option<Arc<TarEntry>> {
        let rel = path.relative();
        if let Some(entry) = self.get_entry_safe(rel) {
            return Some(entry.clone());
        }

        if path.dir_hint() || rel.is_empty() || self.directories.contains(rel) {
            let index_key = path.append_index(default_index);
            if let Some(entry) = self.get_entry_safe(&index_key) {
                return Some(entry.clone());
            }
        }

        if !rel.is_empty() {
            let fallback = format!("{}/{}", rel, default_index);
            if let Some(entry) = self.get_entry_safe(&fallback) {
                return Some(entry.clone());
            }
        } else if let Some(entry) = self.get_entry_safe(default_index) {
            return Some(entry.clone());
        }

        if try_html && !rel.is_empty() && !rel.ends_with(".html") {
            let html_candidate = format!("{rel}.html");
            if let Some(entry) = self.get_entry_safe(&html_candidate) {
                return Some(entry.clone());
            }
        }

        None
    }
}

pub fn is_standalone_script_path(path: &Path) -> bool {
    is_script_c_path(path) || is_script_object_path(path)
}

fn is_script_c_path(path: &Path) -> bool {
    has_extension(path, "c")
}

fn is_script_object_path(path: &Path) -> bool {
    has_extension(path, "o")
}

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|s| s.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

fn standalone_script_name(path: &Path) -> Result<OsString> {
    if is_script_c_path(path) {
        let stem = path
            .file_stem()
            .ok_or_else(|| anyhow::anyhow!("script source path has no file stem"))?;
        let mut name = stem.to_os_string();
        name.push(".o");
        Ok(name)
    } else {
        path.file_name()
            .map(OsStr::to_os_string)
            .ok_or_else(|| anyhow::anyhow!("script object path has no file name"))
    }
}

fn script_object_tarball(file_name: &OsStr, object: &[u8]) -> Result<Vec<u8>> {
    let script_path = Path::new(".zeroserve")
        .join("scripts")
        .join(Path::new(file_name));
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header
        .set_path(&script_path)
        .with_context(|| format!("invalid script object path {}", script_path.display()))?;
    header.set_size(object.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, object)
        .context("failed to append script object to tar")?;
    builder
        .into_inner()
        .context("failed to finalize script object tar")
}

/// Build a fresh in-memory file seeded with `bytes`, for use as a tarball
/// backing file. The returned file is seekable and supports positional reads.
pub fn memfd_from_bytes(name: &str, bytes: &[u8]) -> Result<StdFile> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::memfd::{MFdFlags, memfd_create};
        let cname = std::ffi::CString::new(name).expect("memfd name has no interior NUL");
        let fd = memfd_create(cname.as_c_str(), MFdFlags::MFD_CLOEXEC)
            .with_context(|| format!("memfd_create({name}) failed"))?;
        let mut file = StdFile::from(fd);
        file.write_all(bytes)
            .context("failed to write bytes into memfd")?;
        file.seek(SeekFrom::Start(0))
            .context("failed to rewind memfd")?;
        Ok(file)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Portable fallback: anonymous temp file (unlinked) seeded with the
        // payload. Positional reads work the same as Linux memfd.
        let _ = name;
        let mut file = tempfile::tempfile().context("failed to create anonymous temp file")?;
        file.write_all(bytes)
            .context("failed to write bytes into anonymous temp file")?;
        file.seek(SeekFrom::Start(0))
            .context("failed to rewind anonymous temp file")?;
        Ok(file)
    }
}

#[derive(Clone)]
pub struct NormalizedPath {
    relative: String,
    encoded_relative: String,
    dir_hint: bool,
}

impl NormalizedPath {
    pub fn relative(&self) -> &str {
        &self.relative
    }

    pub fn dir_hint(&self) -> bool {
        self.dir_hint
    }

    pub fn append_index(&self, index: &str) -> String {
        if self.relative.is_empty() {
            index.to_string()
        } else {
            format!("{}/{}", self.relative, index)
        }
    }

    /// Returns the normalized path with original percent-encoding preserved.
    pub fn encoded_path(&self) -> String {
        if self.encoded_relative.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", self.encoded_relative)
        }
    }

    /// Returns the normalized encoded path with a preserved trailing slash hint.
    pub fn encoded_path_with_dir_hint(&self) -> String {
        let mut path = self.encoded_path();
        if self.dir_hint && path != "/" {
            path.push('/');
        }
        path
    }
}

pub fn normalize_request_path(raw: &str) -> Option<NormalizedPath> {
    let normalized_raw = if raw.is_empty() { "/" } else { raw };
    let dir_hint =
        normalized_raw == "/" || (normalized_raw.ends_with('/') && normalized_raw.len() > 1);
    let mut decoded_components = Vec::new();
    let mut raw_components = Vec::new();
    for raw_part in normalized_raw.split('/') {
        if raw_part.is_empty() {
            continue;
        }
        let decoded = percent_decode(raw_part.as_bytes())?;
        if decoded == b"." {
            continue;
        }
        if decoded == b".." {
            decoded_components.pop()?;
            raw_components.pop()?;
            continue;
        }
        // Reject encoded slashes within a segment — a decoded `/` would
        // create a path separator in `relative` that doesn't exist in the
        // encoded view, enabling access-control bypasses.
        if decoded.contains(&b'/') {
            return None;
        }
        let segment = String::from_utf8(decoded).ok()?;
        decoded_components.push(segment);
        raw_components.push(raw_part.to_string());
    }
    let relative = decoded_components.join("/");
    let encoded_relative = raw_components.join("/");
    Some(NormalizedPath {
        relative,
        encoded_relative,
        dir_hint,
    })
}

pub fn guess_mime(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|s| s.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript; charset=utf-8",
        Some("json") => "application/json; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("wasm") => "application/wasm",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("ico") => "image/x-icon",
        _ => "application/octet-stream",
    }
}

fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => {
                let hi = hex_val(input[i + 1])?;
                let lo = hex_val(input[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    Some(out)
}

fn hex_val(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn mark_parents(path: &str, set: &mut HashSet<String>) {
    let mut current = trim_trailing_slash(path);
    if current.is_empty() {
        return;
    }
    while let Some(idx) = current.rfind('/') {
        current = &current[..idx];
        if current.is_empty() {
            break;
        }
        set.insert(current.to_string());
    }
}

fn trim_trailing_slash(path: &str) -> &str {
    path.trim_end_matches('/')
}

pub fn normalize_tar_path(path: &str) -> String {
    path.trim_start_matches("./").trim_matches('/').to_string()
}

fn compute_entry_etag<R: Read>(entry: &mut tar::Entry<R>) -> Result<String> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = entry
            .read(&mut buf)
            .context("failed to read tar entry for etag")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(hex_encode_prefix(&digest.as_bytes()[..16]))
}

fn hex_encode_prefix(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
