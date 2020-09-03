# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import smime

from .utils import load_vectors_from_file


def test_smime_text():
    data = b"the data we want to sign is this amazing sequence of bytes"
    key = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca_key.pem"),
        lambda pemfile: serialization.load_pem_private_key(
            pemfile.read(), None
        ),
        mode="rb",
    )
    cert = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca.pem"),
        loader=lambda pemfile: x509.load_pem_x509_certificate(pemfile.read()),
        mode="rb",
    )
    options = [smime.SMIMEOptions.Text]
    sig = smime.detached_smime_sign(data, cert, key, hashes.SHA256(), options)
    # These assertions are lousy.
    assert sig.find(b"text/plain") > 0
    assert sig.find(b"sha-256") > 0


def test_smime_binary():
    data = b"\x01\x02" * 10
    key = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca_key.pem"),
        lambda pemfile: serialization.load_pem_private_key(
            pemfile.read(), None
        ),
        mode="rb",
    )
    cert = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca.pem"),
        loader=lambda pemfile: x509.load_pem_x509_certificate(pemfile.read()),
        mode="rb",
    )
    options = [smime.SMIMEOptions.Binary]
    sig = smime.detached_smime_sign(data, cert, key, hashes.SHA1(), options)
    # When passing binary no Content-Type is set for the data itself. So there
    # are two Content-Types instead of three. This is a terrible test and we
    # should write a better one.
    assert len(re.findall(b"Content-Type", sig)) == 2
    assert sig.find(b"sha1") == -1
