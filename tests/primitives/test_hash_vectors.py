# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import os

from cryptography.primitives import hashes

from .utils import generate_hash_test, generate_long_string_hash_test
from ..utils import load_hash_vectors_from_file


class TestSHA1(object):
    test_SHA1 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("NIST", "SHABYTE"),
        [
            "SHA1LongMsg.rsp",
            "SHA1ShortMsg.rsp",
        ],
        hashes.SHA1,
        only_if=lambda api: api.supports_hash(hashes.SHA1),
        skip_message="Does not support SHA1",
    )


class TestSHA224(object):
    test_SHA224 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("NIST", "SHABYTE"),
        [
            "SHA224LongMsg.rsp",
            "SHA224ShortMsg.rsp",
        ],
        hashes.SHA224,
        only_if=lambda api: api.supports_hash(hashes.SHA224),
        skip_message="Does not support SHA224",
    )


class TestSHA256(object):
    test_SHA256 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("NIST", "SHABYTE"),
        [
            "SHA256LongMsg.rsp",
            "SHA256ShortMsg.rsp",
        ],
        hashes.SHA256,
        only_if=lambda api: api.supports_hash(hashes.SHA256),
        skip_message="Does not support SHA256",
    )


class TestSHA384(object):
    test_SHA384 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("NIST", "SHABYTE"),
        [
            "SHA384LongMsg.rsp",
            "SHA384ShortMsg.rsp",
        ],
        hashes.SHA384,
        only_if=lambda api: api.supports_hash(hashes.SHA384),
        skip_message="Does not support SHA384",
    )


class TestSHA512(object):
    test_SHA512 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("NIST", "SHABYTE"),
        [
            "SHA512LongMsg.rsp",
            "SHA512ShortMsg.rsp",
        ],
        hashes.SHA512,
        only_if=lambda api: api.supports_hash(hashes.SHA512),
        skip_message="Does not support SHA512",
    )


class TestRIPEMD160(object):
    test_RIPEMD160 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("ISO", "ripemd160"),
        [
            "ripevectors.txt",
        ],
        hashes.RIPEMD160,
        only_if=lambda api: api.supports_hash(hashes.RIPEMD160),
        skip_message="Does not support RIPEMD160",
    )

    test_RIPEMD160_long_string = generate_long_string_hash_test(
        hashes.RIPEMD160,
        "52783243c1697bdbe16d37f97f68f08325dc1528",
        only_if=lambda api: api.supports_hash(hashes.RIPEMD160),
        skip_message="Does not support RIPEMD160",
    )


class TestWhirlpool(object):
    test_whirlpool = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("ISO", "whirlpool"),
        [
            "iso-test-vectors.txt",
        ],
        hashes.Whirlpool,
        only_if=lambda api: api.supports_hash(hashes.Whirlpool),
        skip_message="Does not support Whirlpool",
    )

    test_whirlpool_long_string = generate_long_string_hash_test(
        hashes.Whirlpool,
        ("0c99005beb57eff50a7cf005560ddf5d29057fd86b2"
         "0bfd62deca0f1ccea4af51fc15490eddc47af32bb2b"
         "66c34ff9ad8c6008ad677f77126953b226e4ed8b01"),
        only_if=lambda api: api.supports_hash(hashes.Whirlpool),
        skip_message="Does not support Whirlpool",
    )


class TestMD5(object):
    test_md5 = generate_hash_test(
        load_hash_vectors_from_file,
        os.path.join("RFC", "MD5"),
        [
            "rfc-1321.txt",
        ],
        hashes.MD5,
        only_if=lambda api: api.supports_hash(hashes.MD5),
        skip_message="Does not support MD5",
    )
