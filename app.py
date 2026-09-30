"""KriptoVault - web app enkripsi/dekripsi teks & berkas (Flask)."""
import io
import re

from flask import Flask, jsonify, render_template_string, request, send_file

import crypto_core as cc
import ecb_demo
from PIL import Image

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB


def err(msg, code=400):
    return jsonify(error=msg), code


@app.get("/")
def index():
    return render_template_string(PAGE, algs=list(cc.ALG_ID))


@app.post("/api/text/encrypt")
def enc_text():
    d = request.get_json(force=True, silent=True) or {}
    try:
        blob = cc.encrypt(d.get("text", "").encode("utf-8"), d.get("password", ""),
        d.get("alg", cc.DEFAULT_ALG))
    except ValueError as e:
        return err(str(e))
    out = cc.to_hex(blob) if d.get("fmt") == "hex" else cc.to_base64(blob)
    return jsonify(result=out, size=len(blob))


@app.post("/api/text/decrypt")
def dec_text():
    d = request.get_json(force=True, silent=True) or {}
    try:
        plain = cc.decrypt(cc.from_text(d.get("cipher", "")), d.get("password", ""))
        return jsonify(result=plain.decode("utf-8", errors="replace"))
    except cc.DecryptionError as e:
        return err(str(e))


@app.post("/api/file/encrypt")
def enc_file():
    f = request.files.get("file")
    if not f:
        return err("Berkas belum dipilih")
    try:
        blob = cc.encrypt(f.read(), request.form.get("password", ""),
        request.form.get("alg", cc.DEFAULT_ALG))
    except ValueError as e:
        return err(str(e))
    return send_file(io.BytesIO(blob), as_attachment=True,
    download_name=(f.filename or "berkas") + ".enc",
    mimetype="application/octet-stream")


@app.post("/api/file/decrypt")
def dec_file():
    f = request.files.get("file")
    if not f:
        return err("Berkas belum dipilih")
    try:
        plain = cc.decrypt(f.read(), request.form.get("password", ""))
    except cc.DecryptionError as e:
        return err(str(e))
    name = f.filename or "berkas.enc"
    name = name[:-4] if name.endswith(".enc") else name + ".dec"
    return send_file(io.BytesIO(plain), as_attachment=True, download_name=name,
    mimetype="application/octet-stream")


def _flip_middle(blob: bytes) -> bytes:
    """Ubah 1 bit di byte tengah (untuk demo uji tamper)."""
    b = bytearray(blob)
    b[len(b) // 2] ^= 0x01
    return bytes(b)


@app.post("/api/text/tamper")
def tamper_text():
    d = request.get_json(force=True, silent=True) or {}
    teks = d.get("cipher", "")
    try:
        blob = cc.from_text(teks)
    except cc.DecryptionError as e:
        return err(str(e))
    baru = _flip_middle(blob)
    is_hex = re.fullmatch(r"[0-9a-fA-F\s]+", teks) is not None
    return jsonify(result=cc.to_hex(baru) if is_hex else cc.to_base64(baru))


@app.post("/api/file/tamper")
def tamper_file():
    f = request.files.get("file")
    if not f:
        return err("Berkas belum dipilih")
    data = f.read()
    if len(data) < 2:
        return err("Berkas terlalu kecil")
    return send_file(io.BytesIO(_flip_middle(data)), as_attachment=True,
    download_name=(f.filename or "berkas.enc") + ".rusak",
    mimetype="application/octet-stream")


@app.post("/api/ecb")
def ecb_route():
    f = request.files.get("file")
    if not f:
        return err("Pilih gambar dulu")
    try:
        img = Image.open(f.stream)
    except Exception:
        return err("Berkas bukan gambar yang valid")
    return jsonify(ecb_demo.bandingkan(img))


PAGE = """<!doctype html>
<html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KriptoVault</title>
<style>
body{font-family:system-ui,sans-serif;max-width:820px;margin:24px auto;padding:0 14px;background:#f5f6fa;color:#222}
h1{margin-bottom:4px}.card{background:#fff;border-radius:10px;padding:16px;margin:14px 0;box-shadow:0 1px 4px #0002}
input,select,textarea,button{font:inherit;padding:8px;margin:4px 0;width:100%;box-sizing:border-box}
button{width:auto;background:#2b59c3;color:#fff;border:0;border-radius:6px;cursor:pointer;padding:8px 16px;margin-right:6px}
textarea{min-height:90px;font-family:monospace}.row{display:flex;gap:8px}.row>*{flex:1}
.msg{padding:8px;border-radius:6px;margin-top:6px;display:none}.ok{background:#d9f5df;display:block}.bad{background:#fbdcdc;display:block}
small{color:#666}
</style></head><body>
<h1>🔐 KriptoVault</h1>
<small>Enkripsi modern (AES-256-GCM / ChaCha20-Poly1305) + kunci dari password (scrypt)</small>

<div class="card"><h3>Pengaturan</h3>
<div class="row">
<input id="pw" type="password" placeholder="Password">
<select id="alg">{% for a in algs %}<option>{{a}}</option>{% endfor %}</select>
<select id="fmt"><option value="base64">Base64</option><option value="hex">Heksadesimal</option></select>
</div></div>

<div class="card"><h3>Teks</h3>
<textarea id="plain" placeholder="Tulis teks di sini..."></textarea>
<button onclick="encT()">Enkripsi</button>
<textarea id="cipher" placeholder="Cipherteks (base64/hex)..."></textarea>
<button onclick="decT()">Dekripsi</button>
<button onclick="navigator.clipboard.writeText(cipher.value)">Salin cipherteks</button>
<button onclick="tamperT()" style="background:#b8442b">Simulasi ubah 1 byte</button>
<div id="mt" class="msg"></div></div>

<div class="card"><h3>Berkas (PDF, gambar, dll)</h3>
<input id="file" type="file">
<button onclick="fileOp('encrypt')">Enkripsi berkas</button>
<button onclick="fileOp('decrypt')">Dekripsi berkas (.enc)</button>
<button onclick="fileOp('tamper')" style="background:#b8442b">Simulasi ubah 1 byte (.enc)</button>
<div id="mf" class="msg"></div></div>

<div class="card"><h3>Demo: ECB vs mode aman (citra)</h3>
<small>ECB hanya untuk pembanding. Lihat pola gambar asli masih terlihat pada ECB.</small>
<input id="img" type="file" accept="image/*">
<button onclick="ecb()">Bandingkan</button>
<div class="row"><div><small>Asli</small><img id="i0" style="width:100%"></div>
<div><small>AES-ECB (tidak aman)</small><img id="i1" style="width:100%"></div>
<div><small>AES-256-GCM</small><img id="i2" style="width:100%"></div></div>
<div id="me" class="msg"></div></div>

<script>
const $=id=>document.getElementById(id);
function show(el,ok,t){el.className='msg '+(ok?'ok':'bad');el.textContent=t}
async function jpost(url,body){const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});return [r.ok,await r.json()]}
async function encT(){const [ok,d]=await jpost('/api/text/encrypt',{text:$('plain').value,password:$('pw').value,alg:$('alg').value,fmt:$('fmt').value});
if(ok){$('cipher').value=d.result;show($('mt'),true,'Terenkripsi ('+d.size+' byte)')}else show($('mt'),false,d.error)}
async function decT(){const [ok,d]=await jpost('/api/text/decrypt',{cipher:$('cipher').value,password:$('pw').value});
if(ok){$('plain').value=d.result;show($('mt'),true,'Dekripsi berhasil')}else show($('mt'),false,'❌ '+d.error)}
async function tamperT(){const [ok,d]=await jpost('/api/text/tamper',{cipher:$('cipher').value});
if(ok){$('cipher').value=d.result;show($('mt'),true,'1 bit cipherteks diubah. Coba dekripsi, harus ditolak.')}else show($('mt'),false,d.error)}
async function ecb(){const f=$('img').files[0];if(!f)return show($('me'),false,'Pilih gambar dulu');
const fd=new FormData();fd.append('file',f);const r=await fetch('/api/ecb',{method:'POST',body:fd});const d=await r.json();
if(!r.ok)return show($('me'),false,d.error);$('i0').src=d.asli;$('i1').src=d.ecb;$('i2').src=d.gcm;$('me').className='msg'}
async function fileOp(op){const f=$('file').files[0];if(!f)return show($('mf'),false,'Pilih berkas dulu');
const fd=new FormData();fd.append('file',f);fd.append('password',$('pw').value);fd.append('alg',$('alg').value);
const r=await fetch('/api/file/'+op,{method:'POST',body:fd});
if(!r.ok){const d=await r.json();return show($('mf'),false,'❌ '+d.error)}
const cd=r.headers.get('Content-Disposition')||'';const m=/filename\\*?=(?:UTF-8'')?"?([^";]+)"?/.exec(cd);
const a=document.createElement('a');a.href=URL.createObjectURL(await r.blob());a.download=m?decodeURIComponent(m[1]):'hasil';a.click();
show($('mf'),true,{encrypt:'Berkas terenkripsi, unduhan dimulai',decrypt:'Berkas berhasil didekripsi',tamper:'Berkas .enc diubah 1 bit (.rusak). Coba dekripsi, harus ditolak.'}[op])}
</script></body></html>"""

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
