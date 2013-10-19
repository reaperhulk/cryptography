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

from cryptography.primitives import hashes

from .utils import generate_base_hash_test


class TestSHA1(object):
    test_SHA1 = generate_base_hash_test(
        hashes.SHA1,
        digest_size=20,
        block_size=64,
        only_if=lambda api: api.supports_hash(hashes.SHA1),
        skip_message="Does not support SHA1",
    )


class TestSHA224(object):
    test_SHA224 = generate_base_hash_test(
        hashes.SHA224,
        digest_size=28,
        block_size=64,
        only_if=lambda api: api.supports_hash(hashes.SHA224),
        skip_message="Does not support SHA224",
    )


class TestSHA256(object):
    test_SHA256 = generate_base_hash_test(
        hashes.SHA256,
        digest_size=32,
        block_size=64,
        only_if=lambda api: api.supports_hash(hashes.SHA256),
        skip_message="Does not support SHA256",
    )


class TestSHA384(object):
    test_SHA384 = generate_base_hash_test(
        hashes.SHA384,
        digest_size=48,
        block_size=128,
        only_if=lambda api: api.supports_hash(hashes.SHA384),
        skip_message="Does not support SHA384",
    )


class TestSHA512(object):
    test_SHA512 = generate_base_hash_test(
        hashes.SHA512,
        digest_size=64,
        block_size=128,
        only_if=lambda api: api.supports_hash(hashes.SHA512),
        skip_message="Does not support SHA512",
    )


class TestRIPEMD160(object):
    test_RIPEMD160 = generate_base_hash_test(
        hashes.RIPEMD160,
        digest_size=20,
        block_size=64,
        only_if=lambda api: api.supports_hash(hashes.RIPEMD160),
        skip_message="Does not support RIPEMD160",
    )


class TestWhirlpool(object):
    test_Whirlpool = generate_base_hash_test(
        hashes.Whirlpool,
        digest_size=64,
        block_size=64,
        only_if=lambda api: api.supports_hash(hashes.Whirlpool),
        skip_message="Does not support Whirlpool",
    )


class TestMD5(object):
    test_MD5 = generate_base_hash_test(
        hashes.MD5,
        digest_size=16,
        block_size=64,
        only_if=lambda api: api.supports_hash(hashes.MD5),
        skip_message="Does not support MD5",
    )
