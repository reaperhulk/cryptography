# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from enum import Enum

from cryptography.hazmat.backends import _get_backend


def detached_smime_sign(
    data, certificate, key, hash_algorithm, options, backend=None
):
    backend = _get_backend(backend)
    return backend.detached_smime_sign(
        data, certificate, key, hash_algorithm, options
    )


# TODO: don't leak OpenSSL's magic numbers here
class SMIMEOptions(Enum):
    Binary = 128
    Text = 1
