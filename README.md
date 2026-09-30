# KriptoVault - Aplikasi Enkripsi Modern (Topik A)

Tugas Proyek Keamanan Informasi, Prodi Informatika, Universitas Siliwangi.

**Anggota kelompok**
1.Hikmal Akbar Fauzan NPM 247006111179
2.Wilton Gultom NPM 247006111199
3.Abbdika NPM 247006111190

## Deskripsi
Web app untuk mengenkripsi dan mendekripsi **teks** maupun **berkas** (PDF, gambar, dll).
- Algoritma: **AES-256-GCM** atau **ChaCha20-Poly1305** (AEAD)
- Kunci diturunkan dari password dengan **scrypt** (N=2^15, r=8, p=1) + salt acak 16 byte
- Nonce 12 byte acak (`os.urandom`) tiap enkripsi, disimpan bersama cipherteks
- Cipherteks bisa ditampilkan dalam Base64 atau heksadesimal
- Dekripsi ditolak bila password salah atau cipherteks diubah (verifikasi tag gagal)
- Header berkas ikut menjadi AAD, jadi mengubah salt/nonce/ID algoritma juga terdeteksi

Format blob: `MAGIC(4) | ALG(1) | SALT(16) | NONCE(12) | CIPHERTEXT+TAG(16)`

## Instalasi
```bash
python -m venv .venv
source .venv/bin/activate 
pip install -r requirements.txt
```

## Menjalankan
```bash
python app.py                    
python -m unittest discover -s tests -v   
python benchmark.py              
```

## Contoh penggunaan
1. Isi password, pilih algoritma dan format keluaran.
2. Tab **Teks**: tulis teks, klik *Enkripsi*, salin cipherteks. Tempel lagi lalu klik *Dekripsi*.
3. Tab **Berkas**: pilih PDF, klik *Enkripsi berkas* (hasil `nama.pdf.enc`), lalu *Dekripsi berkas* dengan password yang sama.

## Skenario demo UTS
Enkripsi PDF -> lihat isi cipherteks -> dekripsi password benar (sukses) -> password salah (ditolak) -> ubah satu byte file `.enc` dengan hex editor lalu dekripsi (ditolak).

## Struktur
```
crypto_core.py   inti enkripsi/dekripsi
app.py           web app Flask
benchmark.py     pengujian wajib + fitur pengayaan (ECB vs GCM)
tests/           unit test
results/         hasil_pengujian.xlsx, histogram_entropi.png, perbandingan_ecb_gcm.png
```

## Keamanan
- Tidak ada kunci/password di kode sumber
- ECB hanya dipakai di `benchmark.py` sebagai pembanding visual