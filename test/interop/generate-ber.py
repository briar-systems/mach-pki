#!/usr/bin/env python3
"""re-encode signed data from the cms vectors into ber, for the ber tests

    test/interop/generate-ber.py

ber-openssl-p256-attached.der is openssl-p256-attached.der with indefinite
lengths on the envelope and its content and signature split into two segments
of a constructed octet string. certificates and signed attributes stay der, so
the signature still verifies.

ber-okular-attributes.cms is a genuine okular signature whose first signed
attribute has an indefinite length. the signed attributes are no longer der,
so it must be refused. nothing it carries is signed over, so it does not verify.
"""
import os

vectors = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors", "cms")


def read(b, i):
    """the (tag, children or content, end) of the der or ber element at b[i]"""
    tag = b[i]
    length = b[i + 1]
    i += 2
    if length == 0x80:
        children = []
        while b[i:i + 2] != b"\0\0":
            child, i = read(b, i)
            children.append(child)
        return (tag, children), i + 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(b[i:i + count], "big")
        i += count
    if tag & 0x20:
        children = []
        end = i + length
        while i < end:
            child, i = read(b, i)
            children.append(child)
        return (tag, children), i
    return (tag, b[i:i + length]), i + length


def der(tag, content):
    n = len(content)
    if n < 0x80:
        head = bytes([tag, n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(raw)]) + raw
    return head + content


def encode(node, indefinite):
    tag, body = node
    if isinstance(body, bytes):
        return der(tag, body)
    content = b"".join(encode(c, indefinite) for c in body)
    if id(node) in indefinite:
        return bytes([tag, 0x80]) + content + b"\0\0"
    return der(tag, content)


def segments(tag, data, indefinite):
    half = len(data) // 2
    node = (0x24, [(tag, data[:half]), (tag, data[half:])])
    indefinite.add(id(node))
    return node


def load(name):
    with open(os.path.join(vectors, name), "rb") as f:
        return read(f.read(), 0)[0]


def save(name, node, indefinite):
    with open(os.path.join(vectors, name), "wb") as f:
        f.write(encode(node, indefinite))


# openssl: content info, [0], signed data, encapsulated content, [0] content, signer infos
info = load("openssl-p256-attached.der")
indefinite = set()
explicit = info[1][1]
signed = explicit[1][0]
for node in (info, explicit, signed):
    indefinite.add(id(node))
encapsulated = signed[1][2]
indefinite.add(id(encapsulated))
wrapped = encapsulated[1][1]
indefinite.add(id(wrapped))
wrapped[1][0] = segments(0x04, wrapped[1][0][1], indefinite)
signers = signed[1][-1]
indefinite.add(id(signers))
signer = signers[1][0]
indefinite.add(id(signer))
signer[1][-1] = segments(0x04, signer[1][-1][1], indefinite)
save("ber-openssl-p256-attached.der", info, indefinite)

# okular: the first signed attribute, in the [0] of the signer info
info = load("okular-p384-sha256-1.cms")
signer = info[1][1][1][0][1][-1][1][0]
attributes = next(c for c in signer[1] if c[0] == 0xA0)
save("ber-okular-attributes.cms", info, {id(attributes[1][0])})
