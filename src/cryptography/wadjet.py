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


def _compute_info(frame_length, nonce, final_byte, frame_number):
    return (
        Wadjet._VERSION + utils.int_to_bytes(frame_length) + nonce +
        final_byte + utils.int_to_bytes(frame_number)
    )


def _create_ctx(key, info, operation, tag=None):
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
    def __init__(self, key, frame_length):
        self._key = key
        self._frame_length = frame_length
        self._payload_length = frame_length - Wadjet._FRAME_OVERHEAD
        self._frame_number = 0
        self._buffer = b""
        self._finalized = False
        self._nonce = os.urandom(16)
        self._stream_header = self._generate_stream_header()

    def _generate_stream_header(self):
        frame_length_bytes = utils.int_to_bytes(self._frame_length, 3)
        untagged_stream_header = (
            Wadjet._VERSION + frame_length_bytes + self._nonce
        )
        stream_header_key = HKDFExpand(
            hashes.SHA256(), 32, untagged_stream_header, backend
        ).derive(self._key)
        ctx = Cipher(
            algorithms.AES(stream_header_key),
            modes.GCM(b"\x00" * 12),
            backend
        ).encryptor()
        ctx.authenticate_additional_data(untagged_stream_header)
        ctx.finalize()
        return untagged_stream_header + ctx.tag

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

        if len(data) + len(self._buffer) <= self._payload_length:
            self._buffer += data
            return b"".join(frames)

        while data:
            remaining = self._payload_length - len(self._buffer)
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
        final_byte = b"\x01" if final is True else b"\x00"
        info = _compute_info(
            self._frame_length, self._nonce, final_byte, self._frame_number
        )
        ctx = _create_ctx(self._key, info, Wadjet._ENCRYPT)
        self._frame_number += 1
        ctx.authenticate_additional_data(final_byte)
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
        self._frame_length = None

    def _validate_stream_header(self):
        untagged_stream_header = self._buffer[:-16]
        tag = self._buffer[-16:]
        stream_header_key = HKDFExpand(
            hashes.SHA256(), 32, untagged_stream_header, backend
        ).derive(self._key)
        ctx = Cipher(
            algorithms.AES(stream_header_key),
            modes.GCM(b"\x00" * 12, tag),
            backend
        ).decryptor()
        ctx.authenticate_additional_data(untagged_stream_header)
        try:
            ctx.finalize()
        except InvalidTag:
            raise InvalidFrame

    def _process_stream_header(self):
        if six.indexbytes(self._buffer, 0) != 0x01:
            raise InvalidFrame

        self._frame_length = utils.int_from_bytes(
            self._buffer[1:4], byteorder='big'
        )
        self._nonce = self._buffer[4:20]
        self._payload_length = self._frame_length - Wadjet._FRAME_OVERHEAD
        self._frame_length_bytes = utils.int_to_bytes(
            self._frame_length, 3
        )
        # We've processed the stream header, now drop it from the buffer
        self._buffer = b""

    def update(self, data):
        if self._finalized:
            raise AlreadyFinalized

        utils._check_bytes("data", data)
        if (
            self._nonce is None and
            (len(data) + len(self._buffer)) >= Wadjet._STREAM_HEADER_LENGTH
        ):
            remaining = Wadjet._STREAM_HEADER_LENGTH - len(self._buffer)
            self._buffer += data[:remaining]
            data = data[remaining:]
            self._validate_stream_header()
            self._process_stream_header()
        elif self._nonce is None:
            return b""

        frames = []
        if len(data) + len(self._buffer) < self._frame_length:
            self._buffer += data
            return b""

        while data:
            remaining = self._frame_length - len(self._buffer)
            self._buffer += data[:remaining]
            data = data[remaining:]
            if data:
                frames.append(self._decrypt_frame(final=False))

        return b"".join(frames)

    def finalize(self):
        if self._finalized:
            raise AlreadyFinalized

        self._finalized = True
        # If there's no final frame (frame overhead minimum size) or if
        # the stream header was never processed (nonce is None) then error
        if len(self._buffer) < Wadjet._FRAME_OVERHEAD or self._nonce is None:
            raise InvalidFrame

        return self._decrypt_frame(final=True)

    def _decrypt_frame(self, final):
        tag = self._buffer[-16:]
        final_byte = b"\x01" if final is True else b"\x00"
        info = _compute_info(
            self._frame_length, self._nonce, final_byte, self._frame_number
        )
        ctx = _create_ctx(self._key, info, Wadjet._DECRYPT, tag)
        self._frame_number += 1
        ctx.authenticate_additional_data(final_byte)
        processed_data = ctx.update(self._buffer[1:-16])
        self._buffer = b""
        try:
            ctx.finalize()
        except InvalidTag:
            raise InvalidFrame

        return processed_data


class Wadjet(object):
    _MAX_FRAME_LENGTH = 16777216
    _FRAME_OVERHEAD = 17
    _STREAM_HEADER_LENGTH = 1 + 3 + 16 + 16
    _ENCRYPT = 1
    _DECRYPT = 0
    _VERSION = b"\x01"
    _DEFAULT_FRAME_LENGTH = 1024 ** 2 + _FRAME_OVERHEAD

    def __init__(self, key):
        key = base64.urlsafe_b64decode(key)
        if len(key) != 32:
            raise ValueError(
                "Wadjet key must be 32 url-safe base64-encoded bytes."
            )

        self._key = key

    def _validate_frame_length(self, length):
        if not isinstance(length, six.integer_types):
            raise TypeError("frame_length must be an integer")

        if length > self._MAX_FRAME_LENGTH or length < self._FRAME_OVERHEAD:
            raise ValueError(
                "frame_length must be between {0} and {1}".format(
                    self._FRAME_OVERHEAD,
                    self._MAX_FRAME_LENGTH
                )
            )

    def encryptor(self, frame_length=_DEFAULT_FRAME_LENGTH):
        self._validate_frame_length(frame_length)
        return _WadjetEncryptionContext(self._key, frame_length)

    def decryptor(self):
        return _WadjetDecryptionContext(self._key)

    @classmethod
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))
