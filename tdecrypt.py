#!/usr/bin/env python3

# Titanium Decrypt
# Decrypt Titanium Backup backups
# Copyright 2020, mal@sec.gd

from base64 import b64decode
from getpass import getpass
from hashlib import sha1
import hmac
import logging
import os
import sys
from typing import BinaryIO

# PyCryptodome
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

TB_V1_MAGIC = b"TB_ARMOR_V1"


def titanium_decrypt(enc_file: BinaryIO, out_file: BinaryIO, passphrase: bytes):
    if enc_file.read(len(TB_V1_MAGIC)) != TB_V1_MAGIC:
        raise Exception("Unknown file format. Not encrypted?")
    enc_file.seek(0)
    parts = enc_file.read().split(b"\n", 6)
    (
        header,
        b64_hmac_key,
        b64_hmac_result,
        b64_public_key,
        b64_enc_private_key,
        b64_enc_session_key,
        data,
    ) = parts

    hmac_key = b64decode(b64_hmac_key, validate=True)
    hmac_result = b64decode(b64_hmac_result, validate=True)
    enc_private_key = b64decode(b64_enc_private_key, validate=True)
    enc_session_key = b64decode(b64_enc_session_key, validate=True)

    mac = hmac.digest(hmac_key, passphrase, sha1)
    if mac != hmac_result:
        raise Exception("Incorrect passphrase")

    pass_sha1 = sha1(passphrase).digest()
    key_key = pass_sha1 + b"\0" * (32 - len(pass_sha1))

    aes = AES.new(key_key, AES.MODE_CBC, iv=b"\0" * 16)
    private_key_raw = aes.decrypt(enc_private_key)
    if private_key_raw[-private_key_raw[-1] :] != bytes(
        [private_key_raw[-1]] * private_key_raw[-1]
    ):
        logging.warning("Bad padding on RSA key, this may not work")
    private_key_raw = private_key_raw[: -private_key_raw[-1]]
    private_key = RSA.import_key(private_key_raw)

    rsa = PKCS1_v1_5.new(private_key)
    # rsa = PKCS1_OAEP.new(private_key)
    session_key = rsa.decrypt(enc_session_key, None)
    if session_key is None:
        raise Exception("RSA sentinel returned (decryption error)")

    aes = AES.new(session_key, AES.MODE_CBC, iv=b"\0" * 16)
    out_data = aes.decrypt(data)
    if out_data[-out_data[-1] :] != bytes([out_data[-1]] * out_data[-1]):
        logging.warning("Bad padding on data, writing probably-corrupted file")
    else:
        out_data = out_data[: -out_data[-1]]
    out_file.write(out_data)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        logging.error("Usage: {} encrypted-file.tar")
        exit(1)
    input_file = sys.argv[1]
    if not os.path.isfile(input_file):
        logging.error("Usage: {} encrypted-file.tar")
        exit(1)
    output_file = "decrypted_" + input_file
    if "passphrase" in os.environ:
        passphrase = os.environ["passphrase"].encode("utf-8")
    else:
        passphrase = getpass("Encryption passphrase: ").encode("utf-8")
    with open(input_file, "rb") as f:
        with open(output_file, "wb") as of:
            titanium_decrypt(f, of, passphrase)
