# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
#include <openssl/provider.h>
#endif
"""

TYPES = """
static const long Cryptography_HAS_PROVIDERS;

typedef ... OSSL_PROVIDER;
typedef ... OSSL_LIB_CTX;
"""

FUNCTIONS = """
OSSL_PROVIDER *OSSL_PROVIDER_load(OSSL_LIB_CTX *, const char *);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
static const long Cryptography_HAS_PROVIDERS = 1;
#else
static const long Cryptography_HAS_PROVIDERS = 0;
typedef void OSSL_PROVIDER;
typedef void OSSL_LIB_CTX;
OSSL_PROVIDER *(*OSSL_PROVIDER_load)(OSSL_LIB_CTX *, const char *) = NULL;
#endif
"""
