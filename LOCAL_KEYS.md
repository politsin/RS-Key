<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 RS-Key contributors -->

# Local RP2350-One keys

Both 4 MB keys use the YubiKey-compatible USB identity. BOOTSEL and GP11 are
alternative presence inputs; GP11 is active-high with a pull-down. A touch module
must supply 3.3 V logic and return low when released. Release both inputs before
the next confirmation. The firmware update keeps the existing 4 MB storage map.

| Key | Chip ID / USB serial | YubiKey management serial | Idle colour |
|---|---|---|---|
| Red | `3a5d430fd78f49a0` | `4820951` | Red breathing |
| Green | `10a554ac1906287d` | `19400217` | Green breathing |

Build the ordinary touch-enabled image from the pinned toolchain:

```sh
nix build --impure --file nix/local-touch.nix
```

The output contains `rs-key-waveshare-one-boot-gp11.uf2` and its ELF. Load only
the firmware image, without a full-flash erase or applet reset. The firmware
reports USB build `0x09DB` and Yubico-compatible version `5.8.0`.

Persist the local colours over PC/SC, with one or both known keys attached:

```sh
python tools/configure_local_keys.py
```

Idle, processing and boot use a 2-second breathing effect with brightness 24.
The touch prompt keeps its distinct yellow indication. The script identifies
each chip before writing and verifies the saved configuration by reading it back.

Verify enumeration through the installed Windows Authenticator backend:

```powershell
python tools/verify_windows_keys.py
```

## Validation

On 2026-11-07 both keys were flashed with readback verification. Windows reports
USB build `09DB` and the distinct chip IDs above. The installed Yubico
Authenticator backend and YubiKey Manager enumerate both devices. LED records
were read back after reboot. An untouched presence request timed out on each
key after 30 seconds, without automatic confirmation.

Compilation, Clippy, host tests, firmware variants, image-identity checks,
partition fences and release-image guards passed. The complete repository gate
is **not green**: the unchanged upstream `Cargo.lock` pins `crypto-bigint 0.7.5`
and `ctutils 0.4.2`, affected by
[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html) and
[RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html).
Those advisories concern timing-dependent operations; patched versions are
`crypto-bigint >=0.7.6` and `ctutils >=0.4.4`. Updating and validating the
cryptographic dependency set remains separate from this GPIO/USB configuration
change. The current firmware is not claimed to have a clean dependency audit.
