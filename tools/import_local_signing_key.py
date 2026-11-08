#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 RS-Key contributors

"""Import the local politsin RSA key into empty, protected PIV signature slots.

PIN/PUK entry happens only in the local console. Private material stays in memory;
the optional result file contains public fingerprints and operation status only.
"""

import argparse
import base64
import getpass
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from ykman.device import list_all_devices
from ykman.piv import get_pivman_data, get_pivman_protected_data, pivman_set_mgm_key
from yubikit.core.smartcard import ApduError, SmartCardConnection, SW
from yubikit.piv import (
    DEFAULT_MANAGEMENT_KEY,
    KEY_TYPE,
    MANAGEMENT_KEY_TYPE,
    PIN_POLICY,
    SLOT,
    TOUCH_POLICY,
    PivSession,
)

KEYS = {4820951: "RED", 19400217: "GREEN"}
EXPECTED_FINGERPRINT = "SHA256:KkRSEIn3uG8r9X8WTJWOVhhcu58N6f94TyNx+YrliTU"
FACTORY_PIN = "123456"
FACTORY_PUK = "12345678"


def fingerprint(public_key):
    public = public_key.public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    digest = hashlib.sha256(base64.b64decode(public.split()[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def preflight(device):
    with device.open_connection(SmartCardConnection) as conn:
        session = PivSession(conn)
        try:
            session.get_slot_metadata(SLOT.SIGNATURE)
        except ApduError as error:
            if error.sw != SW.REFERENCE_DATA_NOT_FOUND:
                raise
        else:
            raise RuntimeError("Slot 9c already contains a key; refusing to overwrite")
        if not all(
            metadata.default_value
            for metadata in (
                session.get_pin_metadata(),
                session.get_puk_metadata(),
                session.get_management_key_metadata(),
            )
        ):
            raise RuntimeError("PIV is already configured; refusing to guess credentials")


def secret_prompt(label, minimum, maximum):
    while True:
        first = getpass.getpass(label + ": ")
        if not (minimum <= len(first) <= maximum and first.isascii() and first.isdigit()):
            print(f"Use {minimum} to {maximum} ASCII digits.")
            continue
        if first == getpass.getpass("Repeat: "):
            return first
        print("Values did not match. Try again.")


def certificate_for(key):
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "politsin")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )


def provision(device, serial, key, certificate, pin, puk, state, save):
    result = {"serial": serial, "label": KEYS[serial], "phase": "protecting PIV"}
    state["devices"].append(result)
    save()
    with device.open_connection(SmartCardConnection) as conn:
        session = PivSession(conn)
        session.authenticate(DEFAULT_MANAGEMENT_KEY)
        session.change_pin(FACTORY_PIN, pin)
        result["phase"] = "PIN changed"
        save()
        session.change_puk(FACTORY_PUK, puk)
        result["phase"] = "PUK changed"
        save()
        session.verify_pin(pin)
        management_key = os.urandom(MANAGEMENT_KEY_TYPE.AES256.key_len)
        pivman_set_mgm_key(
            session, management_key, MANAGEMENT_KEY_TYPE.AES256, store_on_device=True
        )
        session.verify_pin(pin)
        if get_pivman_protected_data(session).key != management_key:
            raise RuntimeError("Protected management-key readback mismatch")
        if not get_pivman_data(session).has_stored_key:
            raise RuntimeError("Management-key protection flag is missing")
        session.authenticate(management_key)
        result["phase"] = "PIV protected"
        save()
        key_type = session.put_key(
            SLOT.SIGNATURE, key, PIN_POLICY.ALWAYS, TOUCH_POLICY.ALWAYS
        )
        if key_type != KEY_TYPE.RSA2048:
            raise RuntimeError("Unexpected imported key type")
        result["phase"] = "key imported"
        save()
        session.put_certificate(SLOT.SIGNATURE, certificate)
        metadata = session.get_slot_metadata(SLOT.SIGNATURE)
        imported = session.get_certificate(SLOT.SIGNATURE).public_key()
        if (
            fingerprint(imported) != EXPECTED_FINGERPRINT
            or metadata.pin_policy != PIN_POLICY.ALWAYS
            or metadata.touch_policy != TOUCH_POLICY.ALWAYS
            or metadata.generated
        ):
            raise RuntimeError("Imported key or policy verification failed")
        result["fingerprint"] = fingerprint(imported)
        result["phase"] = "waiting for signing touch"
        save()
        print(f"\nTouch the {KEYS[serial]} key (GP11 sensor or BOOT) NOW.", flush=True)
        session.verify_pin(pin)
        message = b"Local PIV signing verification\x00" + os.urandom(32)
        signature = session.sign(
            SLOT.SIGNATURE, key_type, message, hashes.SHA256(), padding.PKCS1v15()
        )
        imported.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        result["phase"] = "complete"
        result["signature_verified"] = True
        save()
        print(f"{KEYS[serial]}: RSA signature verified; PIN and touch required.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key", type=Path, default=Path("W:/politsin"))
    parser.add_argument("--result", type=Path)
    parser.add_argument("--inspect", action="store_true")
    args = parser.parse_args()
    state = {"status": "preflight", "devices": []}

    def save():
        if args.result:
            args.result.write_text(json.dumps(state, indent=2), encoding="utf8")

    try:
        raw = args.key.read_bytes()
        key = serialization.load_ssh_private_key(raw, password=None)
        del raw
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
            raise RuntimeError("Expected the local RSA-2048 private key")
        if fingerprint(key.public_key()) != EXPECTED_FINGERPRINT:
            raise RuntimeError("Public fingerprint mismatch; refusing to import another key")
        devices = {
            info.serial: device
            for device, info in list_all_devices()
            if info.serial in KEYS
        }
        if set(devices) != set(KEYS):
            raise RuntimeError("Connect both known local keys before proceeding")
        for serial, device in devices.items():
            preflight(device)
            print(f"{KEYS[serial]} {serial}: PIV 9c empty, factory PIV settings confirmed")
        print("Public fingerprint:", EXPECTED_FINGERPRINT)
        if args.inspect:
            return
        print("\nSet a NEW PIV PIN for BOTH keys. This is separate from the FIDO PIN.")
        pin = secret_prompt("New PIV PIN (6-8 digits)", 6, 8)
        puk = secret_prompt("New recovery PUK (8 digits, remember it)", 8, 8)
        if pin == puk or pin == FACTORY_PIN or puk == FACTORY_PUK:
            raise RuntimeError("Choose distinct, non-factory PIN and PUK values")
        print("\nWill protect both PIV applets and import politsin into slot 9c.")
        print("Existing FIDO passkeys and the original W:/politsin file are preserved.")
        input("Press Enter to apply, or Ctrl+C to cancel WITHOUT changes: ")
        certificate = certificate_for(key)
        state["status"] = "running"
        save()
        for serial in KEYS:
            provision(devices[serial], serial, key, certificate, pin, puk, state, save)
        state["status"] = "complete"
        save()
        print("\nSUCCESS: both keys hold the same RSA key and passed hardware signing.")
    except BaseException as error:
        state["status"] = "stopped"
        state["error_type"] = type(error).__name__
        save()
        print(f"Stopped: {type(error).__name__}: {error}", flush=True)
        raise


if __name__ == "__main__":
    main()
