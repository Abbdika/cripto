"""
crypto_core.py
Inti enkripsi untuk aplikasi KriptoVault (Topik A).

Format cipherteks (semua digabung jadi satu blob):
    MAGIC(4) | ALG(1) | SALT(16) | NONCE(12) | CIPHERTEXT + TAG(16)

Header (MAGIC..NONCE) dipakai sebagai AAD, jadi kalau ada byte header
yang diubah orang, tag otomatis gagal diverifikasi.
"""
import base64
import binascii
import os
import re

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"KRP1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32  

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

ALGS = {1: "AES-256-GCM", 2: "ChaCha20-Poly1305"}
ALG_ID = {name: i for i, name in ALGS.items()}
DEFAULT_ALG = "AES-256-GCM"


class DecryptionError(Exception):
    """Dilempar kalau password salah, data diubah, atau format tidak valid."""


def derive_key(password: str, salt: bytes) -> bytes:
    """Turunkan kunci 256-bit dari password memakai scrypt + salt acak."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def _make_cipher(alg: str, key: bytes):
    if alg == "AES-256-GCM":
        return AESGCM(key)
    if alg == "ChaCha20-Poly1305":
        return ChaCha20Poly1305(key)
    raise ValueError(f"Algoritma tidak dikenal: {alg}")


def encrypt_raw(alg: str, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Enkripsi tanpa KDF/header. Dipakai untuk pengujian (avalanche, dll)."""
    return _make_cipher(alg, key).encrypt(nonce, plaintext, aad or None)


def encrypt(data: bytes, password: str, alg: str = DEFAULT_ALG) -> bytes:
    if not password:
        raise ValueError("Password tidak boleh kosong")
    if alg not in ALG_ID:
        raise ValueError(f"Algoritma tidak dikenal: {alg}")
    salt = os.urandom(SALT_LEN)     
    nonce = os.urandom(NONCE_LEN)   
    key = derive_key(password, salt)
    header = MAGIC + bytes([ALG_ID[alg]]) + salt + nonce
    body = _make_cipher(alg, key).encrypt(nonce, data, header)
    return header + body


def decrypt(blob: bytes, password: str) -> bytes:
    min_len = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN + TAG_LEN
    if len(blob) < min_len or blob[:4] != MAGIC:
        raise DecryptionError("Format data tidak valid")
    alg = ALGS.get(blob[4])
    if alg is None:
        raise DecryptionError("ID algoritma tidak dikenal")
    off = 5
    salt = blob[off:off + SALT_LEN]
    off += SALT_LEN
    nonce = blob[off:off + NONCE_LEN]
    off += NONCE_LEN
    header, body = blob[:off], blob[off:]
    key = derive_key(password, salt)
    try:
        return _make_cipher(alg, key).decrypt(nonce, body, header)
    except InvalidTag:
        raise DecryptionError("Password salah atau data sudah diubah (tag tidak cocok)")


def to_base64(blob: bytes) -> str:
    return base64.b64encode(blob).decode("ascii")


def to_hex(blob: bytes) -> str:
    return blob.hex()


def from_text(s: str) -> bytes:
    """Baca cipherteks dari string hex atau base64 (deteksi otomatis)."""
    s = re.sub(r"\s+", "", s)
    if not s:
        raise DecryptionError("Cipherteks kosong")
    try:
        if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
            return bytes.fromhex(s)
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        raise DecryptionError("Cipherteks bukan base64/hex yang valid")
