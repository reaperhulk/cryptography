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


def _create_ctx(key, nonce, final, frame_number, operation, tag=None):
    # Info is: version || nonce || final_byte || frame_number
    final_byte = b"\x01" if final is True else b"\x00"
    info = (
        Wadjet._VERSION + nonce + final_byte +
        utils.int_to_bytes(frame_number)
    )
    expand = HKDFExpand(hashes.SHA256(), 32, info, backend)
    derived_key = expand.derive(key)
    cipher = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(b"\x00" * 12, tag),
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
        self._nonce = os.urandom(16)
        self._stream_header = Wadjet._VERSION + self._nonce

    def update(self, data):
        if self._finalized:
            raise AlreadyFinalized

        utils._check_bytes("data", data)
        frames = []
        # TODO: if you init a ctx and call update with less than a frame's
        # worth of data you'll get back the stream header alone. Do we care?
        if self._stream_header is not None:
            frames.append(self._stream_header)
            self._stream_header = None

        if len(data) + len(self._buffer) <= Wadjet._PAYLOAD_SIZE:
            self._buffer += data
            return b"".join(frames)

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
        frame = self._encrypt_frame(final=True)
        if self._stream_header is not None:
            stream_header_and_frame = self._stream_header + frame
            self._stream_header = None
            return stream_header_and_frame
        else:
            return frame

    def _encrypt_frame(self, final):
        ctx = _create_ctx(
            self._key, self._nonce, final, self._frame_number, Wadjet._ENCRYPT
        )
        self._frame_number += 1
        processed_data = ctx.update(self._buffer)
        ctx.finalize()
        final_byte = b"\x01" if final is True else b"\x00"
        self._buffer = b""
        return b"".join([final_byte, processed_data, ctx.tag])


class _WadjetDecryptionContext(object):
    def __init__(self, key):
        self._key = key
        self._frame_number = 0
        self._buffer = b""
        self._finalized = False
        self._nonce = None

    def update(self, data):
        if self._finalized:
            raise AlreadyFinalized

        # Process the stream header.
        if (
            self._nonce is None and
            (len(data) + len(self._buffer)) >= Wadjet._STREAM_HEADER_SIZE
        ):
            remaining = Wadjet._STREAM_HEADER_SIZE - len(self._buffer)
            self._buffer += data[:remaining]
            data = data[remaining:]
            if six.indexbytes(self._buffer, 0) != 0x01:
                raise InvalidFrame

            self._nonce = self._buffer[1:17]
            # We've processed the stream header, now drop it from the buffer
            self._buffer = b""

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
        if len(self._buffer) < 17:
            raise InvalidFrame

        return self._decrypt_frame(final=True)

    def _decrypt_frame(self, final):
        tag = self._buffer[-16:]
        ctx = _create_ctx(
            self._key, self._nonce, final,
            self._frame_number, Wadjet._DECRYPT, tag
        )
        self._frame_number += 1
        processed_data = ctx.update(self._buffer[1:-16])
        self._buffer = b""
        try:
            ctx.finalize()
        except InvalidTag:
            raise InvalidFrame

        return processed_data


class Wadjet(object):
    _PAYLOAD_SIZE = 1024 ** 2
    _FRAME_SIZE = 1 + _PAYLOAD_SIZE + 16
    _STREAM_HEADER_SIZE = 1 + 16
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
