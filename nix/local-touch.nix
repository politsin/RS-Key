# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

# nix build --impure --file nix/local-touch.nix
let
  source = builtins.getFlake (toString ../.);
  system = "x86_64-linux";
  target = "thumbv8m.main-none-eabihf";
  pkgs = import source.inputs.nixpkgs { inherit system; };
  fx = source.inputs.fenix.packages.${system};
  toolchain = fx.combine [
    fx.stable.rustc
    fx.stable.cargo
    fx.targets.${target}.stable.rust-std
  ];
  firmware = import ./firmware.nix { inherit pkgs target toolchain; };
in
(firmware.lib.mkFirmware {
  name = "rs-key-waveshare-one-boot-gp11";
  vidpid = "Yubikey5";
  flashSize = "4M";
  ledPin = "16";
  ledKind = "ws2812";
  presencePin = "11";
}).overrideAttrs (_: {
  PRESENCE_ACTIVE_HIGH = "1";
  CARGO_BUILD_JOBS = "2";
})
