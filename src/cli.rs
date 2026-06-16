use std::{net::SocketAddr, os::fd::RawFd, path::PathBuf, str::FromStr};

use clap::Parser;

use crate::bpf_compiler::EbpfCompiler;

/// A listen address: either a socket address or a file descriptor.
#[derive(Debug, Clone)]
pub enum ListenAddr {
    /// Bind to a socket address.
    Socket(SocketAddr),
    /// Use an inherited file descriptor (e.g., from socket activation).
    Fd(RawFd),
}

impl FromStr for ListenAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(fd_str) = s.strip_prefix("fd:") {
            let fd: RawFd = fd_str
                .parse()
                .map_err(|e| format!("invalid file descriptor: {e}"))?;
            if fd < 0 {
                return Err("file descriptor must be non-negative".into());
            }
            Ok(ListenAddr::Fd(fd))
        } else {
            let addr: SocketAddr = s
                .parse()
                .map_err(|e| format!("invalid socket address: {e}"))?;
            Ok(ListenAddr::Socket(addr))
        }
    }
}

impl std::fmt::Display for ListenAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListenAddr::Socket(addr) => write!(f, "{}", addr),
            ListenAddr::Fd(fd) => write!(f, "fd:{}", fd),
        }
    }
}

pub fn must_be_positive(value: &str) -> Result<usize, String> {
    let parsed: usize = value.parse().map_err(|e| format!("invalid number: {e}"))?;
    if parsed == 0 {
        Err("value must be greater than zero".into())
    } else {
        Ok(parsed)
    }
}

pub fn default_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Address to bind the HTTP server to. Either ip:port or fd:N for an inherited socket.
    #[arg(long, default_value = "0.0.0.0:8080")]
    pub addr: ListenAddr,

    /// Optional HTTPS address. Either ip:port or fd:N. Requires --cert/--key or --cert-dir.
    #[arg(long)]
    pub tls_addr: Option<ListenAddr>,

    /// TLS certificate (PEM).
    #[arg(long, conflicts_with = "cert_dir")]
    pub cert: Option<PathBuf>,

    /// TLS private key (PEM).
    #[arg(long, conflicts_with = "cert_dir")]
    pub key: Option<PathBuf>,

    /// Directory containing TLS certificate PEMs and private key PEMs.
    #[arg(long, value_name = "DIR", conflicts_with_all = ["cert", "key"])]
    pub cert_dir: Option<PathBuf>,

    /// Default document to serve from directories.
    #[arg(long, default_value_t = String::from(crate::DEFAULT_INDEX))]
    pub index: String,

    /// Maximum chunk size (bytes) for streaming tarball reads.
    #[arg(long, default_value_t = 64 * 1024, value_parser = must_be_positive)]
    pub chunk_size: usize,

    /// Try serving <path>.html when the requested path is missing.
    #[arg(long)]
    pub try_html: bool,

    /// Allow generated Caddy middleware to read from absolute host filesystem roots.
    #[arg(long)]
    pub expose_filesystem: bool,

    /// Comma-separated plugin tarballs or standalone .c/.o scripts. Plugin scripts run before site scripts.
    #[arg(
        long,
        value_name = "PLUGIN_TAR_OR_SCRIPT",
        value_delimiter = ',',
        conflicts_with_all = ["pack", "dump_sdk", "manual", "gen_ech_key"]
    )]
    pub plugin: Vec<PathBuf>,

    /// Unpacked plugin directories. Directory scripts run after --plugin scripts and before site scripts.
    #[arg(
        long,
        value_name = "DIR",
        value_delimiter = ',',
        conflicts_with_all = ["pack", "dump_sdk", "manual", "gen_ech_key"]
    )]
    pub plugin_dir: Vec<PathBuf>,

    /// Pack a directory to stdout as a site tarball.
    #[arg(long, value_name = "DIR", conflicts_with = "tarball")]
    pub pack: Option<PathBuf>,

    /// Compiler for .zeroserve/scripts/*.c and --caddy generated eBPF middleware.
    #[arg(long, value_enum, default_value_t = EbpfCompiler::Tcc)]
    pub ebpf_compiler: EbpfCompiler,

    /// Require async-ebpf static region analysis for loaded eBPF programs.
    #[arg(long)]
    pub ebpf_require_static_region_analysis: bool,

    /// Dump the embedded SDK header to stdout.
    #[arg(long, conflicts_with_all = ["pack", "tarball", "manual"])]
    pub dump_sdk: bool,

    /// Print the embedded user manual to stdout.
    #[arg(long, conflicts_with_all = ["pack", "tarball", "dump_sdk"])]
    pub manual: bool,

    /// Compile a Caddy config into a zeroserve eBPF C request script on stdout.
    /// Accepts either Caddy JSON or a native Caddyfile (auto-detected by content).
    #[arg(long, value_name = "CONFIG", conflicts_with_all = ["pack", "tarball", "dump_sdk", "manual", "gen_ech_key", "caddy"])]
    pub caddy_compile: Option<PathBuf>,

    /// Run a Caddyfile (or Caddy JSON) directly: adapt -> compile -> in-memory
    /// site tarball -> serve, with the generated middleware C and tarball kept
    /// entirely in memory (memfd). Used in place of a SITE_TAR_OR_SCRIPT argument.
    #[arg(long, value_name = "CADDYFILE", conflicts_with_all = ["pack", "tarball", "dump_sdk", "manual", "gen_ech_key", "caddy_compile", "adapt_caddyfile"])]
    pub caddy: Option<PathBuf>,

    /// Adapt a Caddyfile into Caddy JSON and print it to stdout (does not
    /// compile). Useful for inspecting the adapter output.
    #[arg(long, value_name = "CADDYFILE", conflicts_with_all = ["pack", "tarball", "dump_sdk", "manual", "gen_ech_key", "caddy_compile"])]
    pub adapt_caddyfile: Option<PathBuf>,

    /// Generate a new ECH (Encrypted Client Hello) keypair and ECHConfig and
    /// print them to stdout (PEM bundle) and stderr (DNS guidance).
    /// Requires --ech-public-name.
    #[arg(long, conflicts_with_all = ["pack", "tarball", "dump_sdk", "manual"])]
    pub gen_ech_key: bool,

    /// Public name to embed in the generated ECHConfig. The TLS cert served
    /// by the runtime must cover this name. Only meaningful with --gen-ech-key.
    #[arg(long, value_name = "NAME", requires = "gen_ech_key")]
    pub ech_public_name: Option<String>,

    /// Path to an ECH key file or directory of ECH key files. Each file is a
    /// PEM bundle containing one or more (`BEGIN ECH PRIVATE KEY`,
    /// `BEGIN ECH CONFIG`) pairs. Requires TLS to be configured.
    #[arg(long, value_name = "PATH")]
    pub ech_key: Option<PathBuf>,

    /// Path to the site tarball, or a standalone .c/.o script with no static files.
    #[arg(
        value_name = "SITE_TAR_OR_SCRIPT",
        required_unless_present_any = ["pack", "dump_sdk", "manual", "gen_ech_key", "caddy_compile", "adapt_caddyfile", "caddy"],
        conflicts_with = "pack"
    )]
    pub tarball: Option<PathBuf>,

    /// Path to a signal file; polled every second, reloads when content changes.
    #[arg(long, value_name = "FILE")]
    pub reload_signal_file: Option<PathBuf>,

    /// Disable per-request logging.
    #[arg(long)]
    pub disable_request_logging: bool,

    /// Expect a PROXY protocol v1 header before the first request on each connection.
    #[arg(long)]
    pub enable_proxy_protocol: bool,

    /// Disable Linux namespace isolation.
    #[arg(long)]
    pub disable_ns_isolation: bool,

    /// Enable Linux network namespace isolation.
    #[arg(long, conflicts_with = "disable_ns_isolation")]
    pub enable_netns_isolation: bool,

    /// Number of worker threads, each running its own isolated event loop.
    /// Defaults to the number of available CPU cores.
    /// (independently compiled eBPF programs, listeners via SO_REUSEPORT).
    #[arg(long, default_value_t = default_worker_threads(), value_parser = must_be_positive)]
    pub threads: usize,

    /// eBPF async preemption timer interval.
    #[arg(long, default_value_t = 2, value_parser = must_be_positive)]
    pub preempt_timer_interval_ms: usize,

    /// Enable io_uring sqpoll with the provided idle timeout.
    #[arg(long)]
    pub sqpoll_idle_ms: Option<u32>,

    /// Disable proxy protocol decoding fast path for debugging.
    #[arg(long)]
    pub debug_proxy_protocol_disable_fast_path: bool,

    /// Maximum buffered body size in kilobytes for script body reads.
    #[arg(long, default_value_t = 256, value_parser = must_be_positive)]
    pub max_buffered_body_size_kb: usize,

    /// Maximum external memory footprint in kilobytes per request for scripts.
    #[arg(long, default_value_t = 256, value_parser = must_be_positive)]
    pub max_request_external_memory_footprint_kb: usize,

    /// Maximum number of rate limit buckets (unique keys) to track.
    #[arg(long, default_value_t = 10000, value_parser = must_be_positive)]
    pub max_rate_limit_buckets: usize,

    /// JIT code zone size in kibibytes for loaded eBPF scripts, per worker
    /// thread. Must be a multiple of 64. Large compiled middleware (e.g.
    /// Caddy configs with hundreds of sites) may need more than the default.
    #[arg(long, default_value_t = 4096, value_parser = must_be_positive)]
    pub script_code_size_limit_kb: usize,

    /// Comma-separated list of allowed hostnames. Requests with non-matching hostnames receive a 421 error.
    #[arg(long, value_delimiter = ',')]
    pub validate_hostnames: Vec<String>,

    /// Enable the experimental iroh reverse-proxy transport.
    #[cfg(feature = "iroh-proxy")]
    #[arg(long)]
    pub iroh_proxy: bool,

    /// Load or create the local iroh endpoint secret key at this path.
    /// If omitted, ZEROSERVE_IROH_SECRET_KEY may provide a 64-hex key;
    /// otherwise an ephemeral process key is generated.
    #[cfg(feature = "iroh-proxy")]
    #[arg(long, value_name = "FILE", requires = "iroh_proxy")]
    pub iroh_secret_key: Option<PathBuf>,

    /// Disable iroh relay and DNS discovery for local/direct-address testing.
    #[cfg(feature = "iroh-proxy")]
    #[arg(long, requires = "iroh_proxy")]
    pub iroh_disable_networking: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threads_defaults_to_available_parallelism() {
        let cli = Cli::try_parse_from(["zeroserve", "site.tar"]).unwrap();

        assert_eq!(cli.threads, default_worker_threads());
        assert!(cli.threads > 0);
    }

    #[test]
    fn threads_can_be_overridden() {
        let cli = Cli::try_parse_from(["zeroserve", "--threads", "3", "site.tar"]).unwrap();

        assert_eq!(cli.threads, 3);
    }

    #[test]
    fn threads_rejects_zero() {
        let err = Cli::try_parse_from(["zeroserve", "--threads", "0", "site.tar"]).unwrap_err();

        assert!(err.to_string().contains("value must be greater than zero"));
    }

    #[test]
    fn manual_does_not_require_tarball() {
        let cli = Cli::try_parse_from(["zeroserve", "--manual"]).unwrap();

        assert!(cli.manual);
        assert!(cli.tarball.is_none());
    }

    #[test]
    fn manual_conflicts_with_tarball() {
        let err = Cli::try_parse_from(["zeroserve", "--manual", "site.tar"]).unwrap_err();

        assert!(err.to_string().contains("cannot be used with"));
    }

    #[test]
    fn plugin_dir_accepts_comma_delimited_and_repeated_values() {
        let cli = Cli::try_parse_from([
            "zeroserve",
            "--plugin-dir",
            "plugins/auth,plugins/metrics",
            "--plugin-dir",
            "plugins/audit",
            "site.tar",
        ])
        .unwrap();

        assert_eq!(
            cli.plugin_dir,
            vec![
                PathBuf::from("plugins/auth"),
                PathBuf::from("plugins/metrics"),
                PathBuf::from("plugins/audit"),
            ]
        );
    }

    #[test]
    fn ebpf_compiler_defaults_to_tcc() {
        let cli = Cli::try_parse_from(["zeroserve", "site.tar"]).unwrap();

        assert_eq!(cli.ebpf_compiler, EbpfCompiler::Tcc);
    }

    #[test]
    fn ebpf_compiler_accepts_clang() {
        let cli =
            Cli::try_parse_from(["zeroserve", "--ebpf-compiler", "clang", "site.tar"]).unwrap();

        assert_eq!(cli.ebpf_compiler, EbpfCompiler::Clang);
    }

    #[test]
    fn ebpf_require_static_region_analysis_defaults_to_false() {
        let cli = Cli::try_parse_from(["zeroserve", "site.tar"]).unwrap();

        assert!(!cli.ebpf_require_static_region_analysis);
    }

    #[test]
    fn ebpf_require_static_region_analysis_can_be_enabled() {
        let cli = Cli::try_parse_from([
            "zeroserve",
            "--ebpf-require-static-region-analysis",
            "site.tar",
        ])
        .unwrap();

        assert!(cli.ebpf_require_static_region_analysis);
    }
}
