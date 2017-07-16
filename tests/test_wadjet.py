# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend, HashBackend
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.wadjet import AlreadyFinalized, InvalidFrame, Wadjet

from .wadjet_vectors import vectors


@pytest.mark.requires_backend_interface(interface=CipherBackend)
@pytest.mark.requires_backend_interface(interface=HashBackend)
@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 32), modes.GCM(b"\x00" * 12)
    ),
    skip_message="Does not support AES GCM",
)
class TestWadjet(object):
    def test_invalid_key(self):
        with pytest.raises(ValueError):
            Wadjet("nonsense")

    @pytest.mark.parametrize("vector", vectors)
    def test_vectors(self, vector, backend):
        wadjet = Wadjet(vector["key"])
        ctx = wadjet.decryptor()
        if vector["fail"]:
            with pytest.raises(InvalidFrame):
                ctx.update(base64.b64decode(vector["stream"]))
                ctx.finalize()
        else:
            pt = ctx.update(
                base64.b64decode(vector["stream"])
            ) + ctx.finalize()
            assert pt == base64.b64decode(vector["payload"])

    def test_larger_than_one_frame(self):
        key = Wadjet.generate_key()
        wadjet = Wadjet(key)
        ctx = wadjet.encryptor()
        pt = b"0" * 1024 ** 2 + b"1" * 1024
        frames = ctx.update(pt[:1024 ** 2])
        frames += ctx.update(pt[1024 ** 2:]) + ctx.finalize()
        ctx = wadjet.decryptor()
        computed_pt = ctx.update(frames) + ctx.finalize()
        assert computed_pt == pt
        ctx = wadjet.decryptor()
        computed_pt2 = b""
        # TODO: figure out how to make this part of the test vectors. we
        # want lots of incremental updates to test the implementation's
        # buffering code.
        for start in range(0, len(frames), 10000):
            computed_pt2 += ctx.update(frames[start:start+10000])

        computed_pt2 += ctx.finalize()
        assert computed_pt2 == pt

    def test_tamper_final_frame_byte(self):
        # TODO: test vector-ify
        key = Wadjet.generate_key()
        wadjet = Wadjet(key)
        ctx = wadjet.encryptor()
        frames = ctx.update(b"0" * 1024 * 1024)
        frames += ctx.update(b"hello world")
        frames += ctx.finalize()
        truncation_length = (
            Wadjet._DEFAULT_FRAME_LENGTH + Wadjet._STREAM_HEADER_LENGTH
        )
        first_frame = frames[:truncation_length]
        with pytest.raises(InvalidFrame):
            ctx = wadjet.decryptor()
            ctx.update(first_frame)
            ctx.finalize()

        ctx = wadjet.decryptor()
        with pytest.raises(InvalidFrame):
            # Set FinalFrame to 1
            tampered_frame = b"\x01" + first_frame[1:]
            ctx.update(tampered_frame)
            ctx.finalize()

    def test_use_after_finalize(self):
        key = Wadjet.generate_key()
        wadjet = Wadjet(key)
        ctx = wadjet.encryptor()
        frame = ctx.finalize()
        with pytest.raises(AlreadyFinalized):
            ctx.update(b"")

        with pytest.raises(AlreadyFinalized):
            ctx.finalize()

        ctx = wadjet.decryptor()
        ctx.update(frame)
        ctx.finalize()
        with pytest.raises(AlreadyFinalized):
            ctx.update(b"")

        with pytest.raises(AlreadyFinalized):
            ctx.finalize()
