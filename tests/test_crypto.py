import os
import secrets
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_core as cc

PW = secrets.token_urlsafe(16)  

class TestCrypto(unittest.TestCase):
    def test_roundtrip_semua_algoritma(self):
        data = os.urandom(5000)
        for alg in cc.ALG_ID:
            self.assertEqual(cc.decrypt(cc.encrypt(data, PW, alg), PW), data)

    def test_data_kosong(self):
        self.assertEqual(cc.decrypt(cc.encrypt(b"", PW), PW), b"")

    def test_password_salah_ditolak(self):
        blob = cc.encrypt(b"rahasia", PW)
        with self.assertRaises(cc.DecryptionError):
            cc.decrypt(blob, PW + "x")

    def test_satu_byte_berubah_ditolak(self):
        blob = bytearray(cc.encrypt(b"dokumen penting" * 10, PW))
        for pos in (0, 4, 10, 25, 40, len(blob) - 1):
            rusak = bytearray(blob)
            rusak[pos] ^= 0x01
            with self.assertRaises(cc.DecryptionError, msg=f"posisi {pos}"):
                cc.decrypt(bytes(rusak), PW)

    def test_salt_dan_nonce_selalu_beda(self):
        a, b = cc.encrypt(b"sama", PW), cc.encrypt(b"sama", PW)
        self.assertNotEqual(a, b)
        self.assertNotEqual(a[5:21], b[5:21])   # salt
        self.assertNotEqual(a[21:33], b[21:33])  # nonce

    def test_format_base64_dan_hex(self):
        blob = cc.encrypt(b"halo", PW)
        self.assertEqual(cc.from_text(cc.to_base64(blob)), blob)
        self.assertEqual(cc.from_text(cc.to_hex(blob)), blob)

    def test_format_tidak_valid(self):
        for bad in (b"", b"bukan data enkripsi apa pun, cuma teks biasa 1234567890"):
            with self.assertRaises(cc.DecryptionError):
                cc.decrypt(bad, PW)

    def test_password_kosong_ditolak(self):
        with self.assertRaises(ValueError):
            cc.encrypt(b"x", "")


if __name__ == "__main__":
    unittest.main()
