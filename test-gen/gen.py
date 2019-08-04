#!/usr/bin/env python3
import ast
import base64
import os.path


def _range(start, end):
	return bytes(range(start[0], end[0] + 1))


BCRYPT64_TRANS = bytes.maketrans(
	b"./" + _range(b"A", b"Z") + _range(b"a", b"z") + _range(b"0", b"9"),
	_range(b"A", b"Z") + _range(b"a", b"z") + _range(b"0", b"9") + b"+/",
)


def bcrypt64_decode(encoded):
	return base64.b64decode(encoded.translate(BCRYPT64_TRANS) + b"=" * (-len(encoded) % 4), validate=True)


def hex_format(bs):
	return 'b"' + "".join(f"\\x{b:02x}" for b in bs) + '"'


def repr_format(bs):
	return 'b"' + "".join(f"\\x{b:02x}" if b < 32 or b > 126 or b in b'"\\' else chr(b) for b in bs) + '"'


with open(os.path.join(os.path.dirname(__file__), "pyca-test-vectors.py"), "r") as f:
	test_vectors_expr = f.read()

test_vectors = ast.literal_eval(test_vectors_expr)


print("[")

for key, encoded_salt, expected in test_vectors:
	log_rounds = int(encoded_salt[4:6])
	salt = bcrypt64_decode(encoded_salt[7:])
	expected_hash = bcrypt64_decode(expected[7+22:])
	print(f"\t({repr_format(key)}, {log_rounds}, {hex_format(salt)}, {hex_format(expected_hash)}),")

print("]")
