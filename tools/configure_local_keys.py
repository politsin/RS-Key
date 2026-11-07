#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Persist breathing colours on the two local RP2350-One keys over PC/SC."""

from smartcard.System import readers

from rsk import ccid
from rsk.led import COLORS, EFFECTS, STATUSES, _get_block, _status_offset
from rsk.status import RESCUE_AID, rescue_serial

INS_SET_LED = 0x10
BRIGHTNESS = 24
CONFIGURED_STATUSES = ("idle", "processing", "boot")

KEYS = {
    "3a5d430fd78f49a0": "red",
    "10a554ac1906287d": "green",
}


def main():
    configured = set()
    for reader in readers():
        if not ccid._is_rsk(str(reader)):
            continue
        conn = reader.createConnection()
        conn.connect()
        try:
            data, sw1, sw2 = ccid.select(conn, RESCUE_AID)
            raw_serial = rescue_serial(data, sw1, sw2)
            if raw_serial is None:
                raise RuntimeError(f"Cannot identify {reader}")
            chip_id = bytes.fromhex(raw_serial)[::-1].hex()
            if chip_id not in KEYS:
                continue
            label = KEYS[chip_id]
            color = COLORS[label]
            effect = EFFECTS["vapor"]
            _, sw1, sw2 = ccid.select(conn, ccid.VENDOR_AID)
            if (sw1, sw2) != ccid.SW_OK:
                raise RuntimeError(f"Cannot select LED applet on {chip_id}")
            for name in CONFIGURED_STATUSES:
                status = STATUSES[name]
                _, sw1, sw2 = ccid.transmit(
                    conn, [0, INS_SET_LED, BRIGHTNESS, color | (status << 4), 2, effect, 0]
                )
                if (sw1, sw2) != ccid.SW_OK:
                    raise RuntimeError(f"LED write failed on {chip_id}: {sw1:02X}{sw2:02X}")
            block = _get_block(conn)
            for name in CONFIGURED_STATUSES:
                offset = _status_offset(STATUSES[name])
                if block[offset : offset + 4] != bytes([effect, color, BRIGHTNESS, 0]):
                    raise RuntimeError(f"LED readback mismatch on {chip_id}")
            configured.add(chip_id)
            print(f"{chip_id}: {label} breathing verified")
        finally:
            conn.disconnect()
    if not configured:
        raise SystemExit("No known local key connected")


if __name__ == "__main__":
    main()
