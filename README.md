> [!IMPORTANT]
> **Loading this module may cause kernel panic or system instability. Use at your own risk.**

# CVE-2026-31431 Live Mitigation Kernel Module

This Linux kernel module provides a live mitigation for [CVE-2026-31431](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-31431) by disabling the AEAD user API. This performs the same process as when algif_aead.ko is unloaded, preventing vulnerable interfaces from being used from userspace.

## Usage

### Build

1. Ensure you have kernel headers and build tools installed for your running kernel.
2. Build the module:

```bash
make
```

### Install

1. Install the module and configuration file:

```bash
sudo make install
```

2. Load module:
```bash
sudo modprobe cve_2026_31431_live_mitigation
```

### How it works

- On load, the module locates and calls the kernel's `af_alg_unregister_type` function to unregister the `algif_aead` type, disabling the AEAD user API.
- The module cannot be unloaded (no `module_exit`), as this operation is not reversible at runtime.

## Notes

- This mitigation is intended as a temporary measure until a proper kernel update is available.
- Loading this module on an unsupported or incompatible kernel may result in a kernel panic or other critical failures.
- The module is only effective if `algif_aead` is built-in (not as a loadable module).

## Supported environment

Tested on Fedora 42 (6.18.9-100.fc42.x86_64)

## License

GPL-2.0
