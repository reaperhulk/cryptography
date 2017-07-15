# NOTE: This file is not likely to land in a PR. Instead it (or something
# like it) will be used to generate vector files. Right now since Wadjet
# is a probabilistic encryption scheme these vectors change every time
# you create them.

from __future__ import absolute_import, division, print_function

import base64

from cryptography.wadjet import Wadjet


vectors = []


def generate_vector(desc, key, payload):
    wadjet = Wadjet(key)
    ctx = wadjet.encryptor()
    stream = ctx.update(payload) + ctx.finalize()
    return {
        "desc": desc,
        "key": key,
        "payload": base64.b64encode(payload).decode("ascii"),
        "stream": base64.b64encode(stream).decode("ascii"),
        "fail": False,
    }


desc = "zero byte payload"
key = "6Qb6Ulh1_Z0A2jL0oz7P8GXn07OyFYB3wgWtqdbrsaY="
payload = b""
vectors.append(generate_vector(desc, key, payload))

desc = "payload smaller than one full frame"
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"0123456789"
vectors.append(generate_vector(desc, key, payload))

desc = "payload exactly one frame"
key = "DDV-kejnwyL4BJR_-Y1J-2xHvD32M2A5mnG8MFFU7xw="
payload = b"0" * 1024 * 1024
vectors.append(generate_vector(desc, key, payload))

desc = "payload greater than one frame but less than a full two"
key = "4cFefIbulrA_-aUCkmZgNskcPhWQDj_XlIhlQ50ee0c="
payload = b"0" * 1024 * 1027
vectors.append(generate_vector(desc, key, payload))

desc = "payload exactly two frames"
key = "6Vbm8i8-576OjeGtjnSe-tF_InGIB7shGiIxSyfOz4M="
payload = b"0" * 1024 * 1024 + b"1" * 1024 * 1024
vectors.append(generate_vector(desc, key, payload))

desc = "payload > 2 frames"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
payload = b"0" * 1024 * 1024 + b"1" * 1024 * 1024 + b"2" * 100
vectors.append(generate_vector(desc, key, payload))

desc = "reordered frames"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
original_stream = base64.b64decode(vectors[-1]["stream"])
frame_length = 1024 * 1024 + 18
frame0 = original_stream[:frame_length]
frame1 = original_stream[frame_length:frame_length * 2]
frame2 = original_stream[frame_length * 2:]
stream = frame1 + frame0 + frame2
vectors.append({
    "desc": desc,
    "key": key,
    "payload": vectors[-1]["payload"],
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "truncation attack, remove last frame"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
stream = frame0 + frame1
vectors.append({
    "desc": desc,
    "key": key,
    "payload": vectors[-1]["payload"][:frame_length * 2],
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})
