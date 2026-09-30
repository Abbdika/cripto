"""
ecb_demo.py - demo visual perbedaan AES-ECB vs AES-256-GCM pada citra.
ECB di sini HANYA untuk pembanding (memperlihatkan kenapa ECB tidak aman),
tidak dipakai untuk fitur enkripsi utama.
"""
import base64
import io
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

import crypto_core as cc


def _png_b64(size, data):
    buf = io.BytesIO()
    Image.frombytes("RGB", size, data).save(buf, "PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


def bandingkan(img: Image.Image, maks=256):
    img = img.convert("RGB")
    img.thumbnail((maks, maks))
    raw, size = img.tobytes(), img.size
    key = os.urandom(32)
    pad = (-len(raw)) % 16
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ecb = (enc.update(raw + bytes(pad)) + enc.finalize())[:len(raw)]
    gcm = cc.encrypt_raw("AES-256-GCM", key, os.urandom(12), raw)[:len(raw)]
    return {"asli": _png_b64(size, raw), "ecb": _png_b64(size, ecb), "gcm": _png_b64(size, gcm)}
