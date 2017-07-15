# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import os

import six

from cryptography import utils
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


class InvalidFrame(Exception):
    pass


# TODO: do we want to reuse cryptography.exceptions.AlreadyFinalized?
class AlreadyFinalized(Exception):
    pass


def _create_ctx(key, iv, final, frame_number, operation, tag=None):
    # Info is a concatenation of version || final_byte || frame_number || iv
    final_byte = b"\x01" if final is True else b"\x00"
    info = Wadjet._VERSION + final_byte + utils.int_to_bytes(frame_number) + iv
    expand = HKDFExpand(hashes.SHA256(), 32, info, backend)
    derived_key = expand.derive(key)
    cipher = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv, tag),
        backend
    )
    if operation == Wadjet._ENCRYPT:
        return cipher.encryptor()
    else:
        return cipher.decryptor()


class _WadjetEncryptionContext(object):
    def __init__(self, key):
        self._key = key
        self._frame_number = 0
        self._buffer = b""
        self._finalized = False

    def update(self, data):
        if self._finalized:
            raise AlreadyFinalized

        utils._check_bytes("data", data)
        frames = []
        if len(data) + len(self._buffer) <= Wadjet._PAYLOAD_SIZE:
            self._buffer += data
            return b""

        while data:
            remaining = Wadjet._PAYLOAD_SIZE - len(self._buffer)
            self._buffer += data[:remaining]
            data = data[remaining:]
            if data:
                frames.append(self._encrypt_frame(final=False))

        return b"".join(frames)

    def finalize(self):
        if self._finalized:
            raise AlreadyFinalized

        self._finalized = True
        return self._encrypt_frame(final=True)

    def _encrypt_frame(self, final):
        iv = os.urandom(12)
        ctx = _create_ctx(
            self._key, iv, final, self._frame_number, Wadjet._ENCRYPT
        )
        self._frame_number += 1
        processed_data = ctx.update(self._buffer)
        ctx.finalize()
        final_byte = b"\x01" if final is True else b"\x00"
        self._buffer = b""
        return b"".join([b"\x01", final_byte, iv, processed_data, ctx.tag])


class _WadjetDecryptionContext(object):
    def __init__(self, key):
        self._key = key
        self._frame_number = 0
        self._buffer = b""
        self._finalized = False

    def update(self, data):
        if self._finalized:
            raise AlreadyFinalized

        utils._check_bytes("data", data)
        frames = []
        if len(data) + len(self._buffer) < Wadjet._FRAME_SIZE:
            self._buffer += data
            return b""

        while data:
            remaining = Wadjet._FRAME_SIZE - len(self._buffer)
            self._buffer += data[:remaining]
            data = data[remaining:]
            if data:
                frames.append(self._decrypt_frame(final=False))

        return b"".join(frames)

    def finalize(self):
        if self._finalized:
            raise AlreadyFinalized

        self._finalized = True
        if len(self._buffer) < 30:
            raise InvalidFrame

        return self._decrypt_frame(final=True)

    def _decrypt_frame(self, final):
        if (
            six.indexbytes(self._buffer, 0) != 0x01 or
            six.indexbytes(self._buffer, 1) != final
        ):
            raise InvalidFrame

        tag = self._buffer[-16:]
        iv = self._buffer[2:14]
        ctx = _create_ctx(
            self._key, iv, final, self._frame_number, Wadjet._DECRYPT, tag
        )
        self._frame_number += 1
        processed_data = ctx.update(self._buffer[14:-16])
        self._buffer = b""
        try:
            ctx.finalize()
        except InvalidTag:
            raise InvalidFrame

        return processed_data


class Wadjet(object):
    _PAYLOAD_SIZE = 1024 ** 2
    _FRAME_SIZE = 1 + 1 + 12 + _PAYLOAD_SIZE + 16
    _ENCRYPT = 1
    _DECRYPT = 0
    _VERSION = b"\x01"

    def __init__(self, key):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Wadjet key must be 32 url-safe base64-encoded bytes."
            )

        self._key = key

    def encryptor(self):
        return _WadjetEncryptionContext(self._key)

    def decryptor(self):
        return _WadjetDecryptionContext(self._key)

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))
