# NOTE: This file is not likely to land in a PR. Instead it (or something
# like it) will be used to generate vector files. Right now since Wadjet
# is a probabilistic encryption scheme these vectors change every time
# you create them.

from __future__ import absolute_import, division, print_function

import base64

from cryptography.wadjet import Wadjet


header_length = Wadjet._STREAM_HEADER_LENGTH

vectors = []


def generate_vector(desc, frame_length, key, payload, fail=False):
    wadjet = Wadjet(key)
    ctx = wadjet.encryptor(frame_length=frame_length)
    stream = ctx.update(payload) + ctx.finalize()
    return {
        "desc": desc,
        "key": key,
        "payload": base64.b64encode(payload).decode("ascii"),
        "stream": base64.b64encode(stream).decode("ascii"),
        "fail": fail,
    }


desc = "zero length frames rejected"
Wadjet._MIN_FRAME_LENGTH = 17
frame_length = 17
key = "6Qb6Ulh1_Z0A2jL0oz7P8GXn07OyFYB3wgWtqdbrsaY="
payload = b""
vectors.append(generate_vector(desc, frame_length, key, payload, True))
Wadjet._MIN_FRAME_LENGTH = 18

desc = "minimum frame size"
frame_length = 18
key = "6Qb6Ulh1_Z0A2jL0oz7P8GXn07OyFYB3wgWtqdbrsaY="
payload = b"!"
vectors.append(generate_vector(desc, frame_length, key, payload))

desc = "payload smaller than one full frame"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234"
vectors.append(generate_vector(desc, frame_length, key, payload))

desc = "payload exactly one frame"
key = "DDV-kejnwyL4BJR_-Y1J-2xHvD32M2A5mnG8MFFU7xw="
frame_length = 50
payload_length = frame_length - Wadjet._FRAME_OVERHEAD
payload = b"0" * payload_length
vectors.append(generate_vector(desc, frame_length, key, payload))

desc = "payload greater than one frame but less than a full two"
key = "4cFefIbulrA_-aUCkmZgNskcPhWQDj_XlIhlQ50ee0c="
frame_length = 30
payload_length = frame_length - Wadjet._FRAME_OVERHEAD
payload = b"0" * payload_length + b"0" * 5
vectors.append(generate_vector(desc, frame_length, key, payload))

desc = "payload exactly two frames"
key = "6Vbm8i8-576OjeGtjnSe-tF_InGIB7shGiIxSyfOz4M="
frame_length = 25
payload_length = frame_length - Wadjet._FRAME_OVERHEAD
payload = b"0" * payload_length + b"1" * payload_length
vectors.append(generate_vector(desc, frame_length, key, payload))

desc = "payload > 2 frames"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
frame_length = 25
payload_length = frame_length - Wadjet._FRAME_OVERHEAD
payload = (
    b"0" * payload_length + b"1" * payload_length + b"2" * 100
)
vectors.append(generate_vector(desc, frame_length, key, payload))

# decrypt vector only, no need to include payload
desc = "reordered frames"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
frame_length = 25
original_stream = base64.b64decode(vectors[-1]["stream"])
header = original_stream[:header_length]
frame0 = original_stream[header_length:header_length+frame_length]
frame1 = original_stream[
    header_length+frame_length:header_length+(frame_length*2)
]
frame2 = original_stream[header_length+frame_length*2:]
stream = header + frame1 + frame0 + frame2
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

# decrypt vector only, no need to include payload
desc = "truncation attack, remove last frame"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
stream = header + frame0 + frame1
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

# decrypt vector only
desc = "interleave attack"
key = "zJ71uJB3pXa4uSKs7qSz5faudEo1j-BatZ7H2g1nkLg="
frame_length = 25
payload_length = frame_length - Wadjet._FRAME_OVERHEAD
payload0 = b"0" * payload_length + b"1" * payload_length
payload1 = b"1" * payload_length + b"0" * payload_length
vector0 = generate_vector(desc, frame_length, key, payload0)
vector1 = generate_vector(desc, frame_length, key, payload1)
# The interleave attack we'll try is grabbing the stream header and
# frame0 of vector0 and frame1 of vector1. This will result in a payload of
# all 0s for two full frames, but should fail because each frame stream has
# a different nonce.
stream = (
    base64.b64decode(vector0["stream"])[:frame_length+header_length] +
    base64.b64decode(
        vector1["stream"]
    )[frame_length+header_length:frame_length*2+header_length]
)
assert len(stream) == 2 * frame_length + header_length
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper with the version in stream header"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234"
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
stream[0] = 0
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper with the nonce in stream header"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234"
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
# set the nonce to null
for i in range(4, 20):
    stream[i] = 0
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper with the stream header tag"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234"
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
# set the tag to null bytes
for i in range(20, 36):
    stream[i] = 0
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper with the frame length in stream header"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234"
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
# Set the frame length to 255
stream[1] = 0
stream[2] = 0
stream[3] = 0xff
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper the final frame byte"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234" * 3
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
stream[36] = 1
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper the ciphertext frame 1"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234" * 3
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
# XOR it so we can guarantee it changes
stream[37] = stream[37] ^ 20
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper the ciphertext frame 2"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234" * 3
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
# XOR it so we can guarantee it changes
stream[63] = stream[63] ^ 20
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

desc = "tamper the frame tag"
frame_length = 25
key = "iEWMb2DUU8FcsliwJyjM-KlSgwXeyJNF0-j9UAP0PHc="
payload = b"01234"
wadjet = Wadjet(key)
ctx = wadjet.encryptor(frame_length=frame_length)
stream = ctx.update(payload) + ctx.finalize()
stream = bytearray(stream)
# XOR it so we can guarantee it changes
stream[-12] = stream[-12] ^ 20
vectors.append({
    "desc": desc,
    "key": key,
    "stream": base64.b64encode(stream).decode("ascii"),
    "fail": True
})

# import json
# with open("/Users/pkehrer/Desktop/vectors.json", "w") as f:
#     json.dump(vectors, f, indent=2)
