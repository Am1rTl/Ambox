from __future__ import annotations

import base64
from typing import Any
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import load_der_private_key

from app.happ_crypto_keys import CRYPT5_KEYS, PKCS1_KEYS


class HappCryptoError(ValueError):
    pass


def b64_decode_urlsafe(s: str) -> bytes:
    clean = "".join(c for c in s if c not in " \t\r\n").replace("-", "+").replace("_", "/")
    pad = (4 - len(clean) % 4) % 4
    clean += "=" * pad
    try:
        return base64.b64decode(clean)
    except Exception as exc:
        raise HappCryptoError(f"invalid base64 payload: {exc}") from exc


def happ_swap_block_halves(b: bytes) -> bytearray:
    out = bytearray(b)
    for i in range(0, len(out) - 3, 4):
        out[i], out[i + 2] = out[i + 2], out[i]
        out[i + 1], out[i + 3] = out[i + 3], out[i + 1]
    return out


def happ_swap_adjacent(b: bytes) -> bytearray:
    out = bytearray(b)
    for i in range(0, len(out) - 1, 2):
        out[i], out[i + 1] = out[i + 1], out[i]
    return out


_PARSED_PKCS1_KEYS: dict[str, Any] = {}
_PARSED_CRYPT5_KEYS: dict[str, Any] = {}


def _get_pkcs1_key(version: str) -> Any:
    key_name = "crypt" if version in {"crypt", "crypt1"} else version
    if key_name not in PKCS1_KEYS:
        raise HappCryptoError(f"unknown Happ crypt version: {version}")
    if key_name not in _PARSED_PKCS1_KEYS:
        der = base64.b64decode(PKCS1_KEYS[key_name])
        _PARSED_PKCS1_KEYS[key_name] = load_der_private_key(der, password=None)
    return _PARSED_PKCS1_KEYS[key_name]


def _get_crypt5_key(marker: str) -> Any:
    if marker not in CRYPT5_KEYS:
        raise HappCryptoError(f"unknown Happ crypt5 key marker: {marker}")
    if marker not in _PARSED_CRYPT5_KEYS:
        der = base64.b64decode(CRYPT5_KEYS[marker])
        _PARSED_CRYPT5_KEYS[marker] = load_der_private_key(der, password=None)
    return _PARSED_CRYPT5_KEYS[marker]


def decrypt_crypt1to4(payload: str, preferred_version: str = "crypt") -> str:
    versions_to_try = [preferred_version]
    for v in ("crypt", "crypt2", "crypt3", "crypt4"):
        if v not in versions_to_try:
            versions_to_try.append(v)

    last_error: Exception | None = None
    for version in versions_to_try:
        try:
            key = _get_pkcs1_key(version)
            cipher_bytes = b64_decode_urlsafe(payload)
            key_size = (key.key_size + 7) // 8
            if len(cipher_bytes) % key_size != 0:
                continue

            plaintext = bytearray()
            for i in range(0, len(cipher_bytes), key_size):
                chunk = cipher_bytes[i : i + key_size]
                decrypted_chunk = key.decrypt(chunk, padding.PKCS1v15())
                plaintext.extend(decrypted_chunk)

            text = plaintext.decode("utf-8")
            if text:
                return text
        except Exception as exc:
            last_error = exc
            continue

    raise HappCryptoError(f"failed to decrypt Happ payload: {last_error or 'invalid blocks'}")


def _decrypt_crypt5_body(body: bytes, key: Any, salted: bool) -> str:
    nonce_size = 12
    if len(body) < nonce_size + 1:
        raise HappCryptoError("crypt5 body too short")

    nonce = bytes(body[:nonce_size])
    salt_offset = 14
    salt_size = 8

    if salted:
        if len(body) < salt_offset + salt_size + 1:
            raise HappCryptoError("crypt5 salted body too short")
        salt = bytes(body[salt_offset : salt_offset + salt_size])
        length_start = salt_offset + salt_size
    else:
        salt = b""
        length_start = nonce_size

    length_end = length_start
    while length_end < len(body) and chr(body[length_end]).isdigit():
        length_end += 1

    if length_end == length_start:
        raise HappCryptoError("crypt5 segment length missing")

    segment_length = int(body[length_start:length_end].decode("ascii"))
    packed = body[length_end:]
    if len(packed) < segment_length + 2:
        raise HappCryptoError("crypt5 segment truncated")

    sealed_url = packed[1 : segment_length + 1].decode("latin1")
    rsa_block = packed[segment_length + 1 :].decode("latin1")

    rsa_ciphertext = b64_decode_urlsafe(rsa_block)
    rsa_plaintext = key.decrypt(rsa_ciphertext, padding.PKCS1v15())
    chacha_key = bytearray(b64_decode_urlsafe(bytes(happ_swap_adjacent(rsa_plaintext)).decode("latin1")))

    if len(chacha_key) != 32:
        raise HappCryptoError(f"crypt5 key must be 32 bytes, got {len(chacha_key)}")

    if salt:
        for i in range(len(chacha_key)):
            chacha_key[i] ^= salt[i % len(salt)]

    ciphertext = b64_decode_urlsafe(sealed_url)
    aead = ChaCha20Poly1305(bytes(chacha_key))
    intermediate = aead.decrypt(nonce, ciphertext, None)
    plaintext = b64_decode_urlsafe(bytes(happ_swap_adjacent(intermediate)).decode("latin1"))
    return plaintext.decode("utf-8")


def decrypt_crypt5(payload: str) -> str:
    shuffled = happ_swap_block_halves(payload.encode("latin1"))
    if len(shuffled) < 8:
        raise HappCryptoError("crypt5 payload is too short")

    marker = shuffled[:4].decode("latin1") + shuffled[-4:].decode("latin1")
    key = _get_crypt5_key(marker)
    body = bytes(shuffled[4:-4])

    is_salted = len(body) > 12 and not chr(body[12]).isdigit()
    for attempt_salted in (is_salted, not is_salted):
        try:
            return _decrypt_crypt5_body(body, key, attempt_salted)
        except Exception:
            pass

    raise HappCryptoError("failed to decrypt Happ crypt5 payload")


def decrypt_happ_payload(action: str, payload: str) -> str:
    act = action.lower()
    if act == "crypt5":
        return decrypt_crypt5(payload)
    if act in {"crypt", "crypt1", "crypt2", "crypt3", "crypt4"}:
        return decrypt_crypt1to4(payload, act)
    raise HappCryptoError(f"unsupported crypt action: {action}")
