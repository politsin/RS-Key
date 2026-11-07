#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Check both local keys through Yubico Authenticator's installed backend."""

import argparse
import json
import subprocess

YUBIKEY5_PID = 0x0407
RPC_TIMEOUT_SECS = 20
EXPECTED = {"4820951": "red", "19400217": "green"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--helper",
        default=r"C:\Program Files\Yubico\Yubico Authenticator\helper\authenticator-helper.exe",
    )
    args = parser.parse_args()
    request = {"kind": "command", "action": "get", "target": ["usb"]}
    result = subprocess.run(
        [args.helper],
        input=json.dumps(request) + "\n",
        capture_output=True,
        text=True,
        encoding="utf8",
        timeout=RPC_TIMEOUT_SECS,
        check=True,
    )
    response = json.loads(result.stdout)
    if response.get("kind") != "success":
        raise SystemExit(f"Authenticator USB scan failed: {response}")
    devices = response["body"]["children"]
    missing = EXPECTED.keys() - devices.keys()
    if missing:
        raise SystemExit(f"Authenticator cannot see local keys: {sorted(missing)}")
    for serial, label in EXPECTED.items():
        device = devices[serial]
        if device.get("serial") != int(serial) or device.get("pid") != YUBIKEY5_PID:
            raise SystemExit(f"Unexpected identity for {label}: {device}")
        print(f"Yubico Authenticator: {label} {device['name']} serial={serial} OK")


if __name__ == "__main__":
    main()
