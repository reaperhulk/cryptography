# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from enum import Enum

from cryptography import x509
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.primitives import hashes
from cryptography.utils import _check_byteslike


class SMIMESignatureBuilder(object):
    def __init__(self, data=None, signers=[]):
        self._data = data
        self._signers = signers

    def add_data(self, data):
        _check_byteslike("data", data)
        if self._data is not None:
            raise ValueError("data may only be set once")

        return SMIMESignatureBuilder(data, self._signers)

    def add_signer(self, certificate, key, hash_algorithm):
        if not isinstance(hash_algorithm, hashes.HashAlgorithm):
            raise TypeError("hash_algorithm must be a hash")
        if not isinstance(certificate, x509.Certificate):
            raise TypeError("certificate must be a x509.Certificate")
        # TODO: check key somehow

        return SMIMESignatureBuilder(
            self._data, self._signers + [(certificate, key, hash_algorithm)]
        )

    def sign(self, encoding, options, backend=None):
        if len(self._signers) == 0:
            raise ValueError("Must have at least one signer")
        if self._data is None:
            raise ValueError("You must add data to sign")

        backend = _get_backend(backend)
        return backend.smime_sign(self, encoding, options)


class SMIMEOptions(Enum):
    Text = "Add text/plain MIME type"
    Binary = "Don't translate input data into canonical MIME format"
    DetachedSignature = "Don't embed data in the PKCS7 structure"
    NoCapabilities = "Don't embed SMIME capabilities"
    NoAttributes = "Don't embed authenticatedAttributes"


class SMIMEEncoding(Enum):
    Binary = "BER/DER encoding"
    PEM = "PEM encoded BER/DER data with S/MIME headers"
