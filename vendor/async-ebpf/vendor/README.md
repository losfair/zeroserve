# Vendored Dependencies

## uBPF

`vendor/ubpf` was vendored from `https://github.com/iovisor/ubpf` at:

```text
d340f8281e5c6b13e009e41fc723f3e1ad96e94f
2026-04-02 09:03:34 -0700
Validate LDDW second-half instruction fields (#764)
```

The vendored tree is intentionally patched for async-ebpf's private JIT pointer
cage integration. Re-vendoring should start from the commit above or a newer
upstream commit, then re-apply the local pointer-cage JIT changes.
