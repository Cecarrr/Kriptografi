import os
import streamlit as st
import pandas as pd
from Crypto.Cipher import ChaCha20  # Menggunakan library yang sama dengan AES

st.set_page_config(page_title="Murni ChaCha20", page_icon="🔐", layout="wide")

# =========================================================
# BAGIAN 1: IMPLEMENTASI MANUAL RFC 8439 — KHUSUS VISUALISASI
# (tidak dipakai untuk enkripsi/dekripsi data sungguhan di tab 1 & 2)
# =========================================================

MASK32 = 0xFFFFFFFF

def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32

def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = rotl(s[b], 7)

def quarter_round_trace(a: int, b: int, c: int, d: int) -> list:
    steps = []
    a = (a + b) & MASK32; d ^= a; d = rotl(d, 16)
    steps.append(("a += b ; d ^= a ; d <<<= 16", a, b, c, d))
    c = (c + d) & MASK32; b ^= c; b = rotl(b, 12)
    steps.append(("c += d ; b ^= c ; b <<<= 12", a, b, c, d))
    a = (a + b) & MASK32; d ^= a; d = rotl(d, 8)
    steps.append(("a += b ; d ^= a ; d <<<= 8", a, b, c, d))
    c = (c + d) & MASK32; b ^= c; b = rotl(b, 7)
    steps.append(("c += d ; b ^= c ; b <<<= 7", a, b, c, d))
    return steps

def chacha20_init_state(key: bytes, nonce: bytes, counter: int) -> list:
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    kw = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    nw = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 8, 4)] # ChaCha20 standar pycryptodome pakai 8 byte nonce
    # Padding nonce jadi 12 byte (standar manual RFC) untuk keperluan visualisasi agar pas matriks
    if len(nw) == 2: nw = [0] + nw 
    return constants + kw + [counter] + nw

def chacha20_block_with_trace(key: bytes, nonce: bytes, counter: int):
    state = chacha20_init_state(key, nonce, counter)
    w = state.copy()
    snapshots = []
    for _ in range(10):  # 10 double-round = 20 round
        quarter_round(w, 0, 4, 8, 12); quarter_round(w, 1, 5, 9, 13)
        quarter_round(w, 2, 6, 10, 14); quarter_round(w, 3, 7, 11, 15)
        quarter_round(w, 0, 5, 10, 15); quarter_round(w, 1, 6, 11, 12)
        quarter_round(w, 2, 7, 8, 13); quarter_round(w, 3, 4, 9, 14)
        snapshots.append(w.copy())
    out = [(w[i] + state[i]) & MASK32 for i in range(16)]
    keystream = b"".join(x.to_bytes(4, "little") for x in out)
    return keystream, state, snapshots

def chacha20_block(key: bytes, nonce: bytes, counter: int) -> bytes:
    ks, _, _ = chacha20_block_with_trace(key, nonce, counter)
    return ks

def grid(state: list) -> str:
    return "\n".join(" ".join(f"{w:08x}" for w in state[r * 4:(r + 1) * 4]) for r in range(4))

# =========================================================
# BAGIAN 1.5: HELPER EDUKASI & VISUALISASI
# =========================================================

def hex_dec(x: int, hex_width: int = 8) -> str:
    return f"`0x{x:0{hex_width}x}` (desimal: **{x}**)"

def flow_diagram(items: list, note: str = None):
    parts = []
    for i, it in enumerate(items):
        sub = it.get("sub", "")
        sub_html = f'<div style="font-size:12px;color:#888;margin-top:6px;text-align:center;">{sub}</div>' if sub else ""
        box = f'<div style="display:flex;flex-direction:column;align-items:center;max-width:150px;"><div style="background:#2b6cb0;color:#fff;border-radius:10px;padding:10px 14px;text-align:center;font-weight:600;font-size:14px;">{it["label"]}</div>{sub_html}</div>'
        parts.append(box)
        if i < len(items) - 1:
            parts.append('<div style="font-size:24px;color:#aaa;padding:0 10px;align-self:center;">→</div>')
    html = '<div style="display:flex;align-items:flex-start;justify-content:center;flex-wrap:wrap;gap:2px;padding:14px 0;">' + "".join(parts) + "</div>"
    st.markdown(html, unsafe_allow_html=True)
    if note: st.caption(note)

def render_hexdec_crash_course():
    contoh = [(0, "0000"), (5, "0101"), (10, "1010"), (15, "1111"), (255, "1111 1111")]
    df = pd.DataFrame([{"Hex": f"0x{h:X}", "Desimal": h, "Biner": b} for h, b in contoh])
    st.dataframe(df, use_container_width=True)

def val_hex(x: int, hex_width: int = 2) -> str:
    return f"{x} (0x{x:0{hex_width}x})"

def tabel_xor_byte(bytes_a: bytes, keystream: bytes, bytes_hasil: bytes, label_a="Plaintext", label_hasil="Ciphertext", char_from="a"):
    sumber_karakter = bytes_a if char_from == "a" else bytes_hasil
    rows = []
    for i in range(len(bytes_a)):
        pa, pb, ph = bytes_a[i], keystream[i], bytes_hasil[i]
        ch_val = sumber_karakter[i]
        ch = chr(ch_val) if 32 <= ch_val <= 126 else "·"
        rows.append({"Posisi": i + 1, "Karakter": ch, label_a: val_hex(pa), "Keystream": val_hex(pb), label_hasil: val_hex(ph)})
    st.dataframe(pd.DataFrame(rows), use_container_width=True)

# =========================================================
# BAGIAN 2: ENKRIPSI/DEKRIPSI SESUNGGUHNYA — Murni ChaCha20
# =========================================================

def real_encrypt(key: bytes, plaintext: bytes):
    cipher = ChaCha20.new(key=key) # PyCryptodome akan otomatis generate 8-byte nonce
    ciphertext = cipher.encrypt(plaintext)
    return cipher.nonce, ciphertext

def real_decrypt(key: bytes, nonce: bytes, ciphertext: bytes):
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt(ciphertext)

# =========================================================
# BAGIAN 3: ANTARMUKA STREAMLIT
# =========================================================

st.title("ChaCha20 (Stream Cipher)")
st.caption("Algoritma kriptografi modern (Tanpa Poly1305 / Murni Enkripsi)")

if "key" not in st.session_state:
    st.session_state.key = os.urandom(32)

with st.sidebar:
    st.subheader("Kunci (Key)")
    key_hex = st.text_input("Key — hex, 64 karakter (32 byte)", value=st.session_state.key.hex())
    if st.button("Generate key acak"):
        st.session_state.key = os.urandom(32)
        st.rerun()
    try:
        key = bytes.fromhex(key_hex)
        assert len(key) == 32
    except (ValueError, AssertionError):
        st.error("Key harus 64 karakter hex (32 byte).")
        st.stop()

tab_enc, tab_dec, tab_proses = st.tabs(["Enkripsi", "Dekripsi", "Visualisasi Proses Lengkap"])

# ---------------------------------------------------------
# TAB ENKRIPSI
# ---------------------------------------------------------
with tab_enc:
    plaintext = st.text_area("Plaintext", height=120, placeholder="Tulis pesan...")
    if st.button("Enkripsi", type="primary"):
        if not plaintext:
            st.warning("Plaintext tidak boleh kosong.")
        else:
            nonce, ciphertext = real_encrypt(key, plaintext.encode())
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Nonce (hex, 8-byte)**")
                st.code(nonce.hex(), language="text")
            with c2:
                st.markdown("**Ciphertext (hex)**")
                st.code(ciphertext.hex(), language="text")

# ---------------------------------------------------------
# TAB DEKRIPSI
# ---------------------------------------------------------
with tab_dec:
    c1, c2 = st.columns(2)
    with c1:
        nonce_in = st.text_input("Nonce (hex)")
    with c2:
        ct_in = st.text_area("Ciphertext (hex)", height=100)

    if st.button("Dekripsi", type="primary"):
        try:
            n, c = bytes.fromhex(nonce_in), bytes.fromhex(ct_in)
            pt = real_decrypt(key, n, c)
            st.success("Berhasil dibuka.")
            st.markdown("**Plaintext hasil dekripsi**")
            st.code(pt.decode(errors="replace"), language="text")
        except Exception as e:
            st.error(f"Gagal: Format hex salah atau data korup. Error: {e}")

# ---------------------------------------------------------
# TAB VISUALISASI PROSES LENGKAP 
# ---------------------------------------------------------
with tab_proses:
    st.markdown("Tab ini membedah cara ChaCha20 membuat **keystream** angka acak menggunakan *Bitwise Rotation* dan penambahan Matriks (ARX).")
    msg = st.text_area("Pesan untuk divisualisasikan (maks 32 karakter)", value="Halo ChaCha20!", height=70)
    
    if len(msg.encode()) > 32:
        msg = msg.encode()[:32].decode(errors="ignore")
        st.caption(f"Pesan dipotong otomatis jadi 32 byte pertama: \"{msg}\"")

    if st.button("Jalankan Visualisasi", type="primary"):
        if not msg:
            st.warning("Pesan kosong.")
        else:
            pt_bytes = msg.encode()
            nonce = os.urandom(8)  # 8 byte sesuai pycryptodome standar
            
            keystream1, state0, snapshots0 = chacha20_block_with_trace(key, nonce, 1)
            ciphertext = bytes(a ^ b for a, b in zip(pt_bytes, keystream1))
            recovered = bytes(a ^ b for a, b in zip(ciphertext, keystream1))

            st.session_state.viz = dict(
                msg=msg, pt_bytes=pt_bytes, nonce=nonce,
                state0=state0, snapshots0=snapshots0,
                keystream1=keystream1, ciphertext=ciphertext, recovered=recovered,
            )
            st.session_state.viz_step = 0

    if "viz" in st.session_state:
        V = st.session_state.viz
        STEP_NAMES = ["0. Persiapan Bahan", "1. Acak Matriks (Quarter Round)", "2. XOR Plaintext (Enkripsi)", "3. XOR Ciphertext (Dekripsi)"]
        
        st.divider()
        nav1, nav2, nav3 = st.columns([1, 3, 1])
        with nav1:
            if st.button("⬅ Sebelumnya", disabled=st.session_state.viz_step == 0, use_container_width=True): st.session_state.viz_step -= 1
        with nav2:
            pilih = st.selectbox("Lompat ke langkah", STEP_NAMES, index=st.session_state.viz_step)
            st.session_state.viz_step = STEP_NAMES.index(pilih)
        with nav3:
            if st.button("Selanjutnya ➡", disabled=st.session_state.viz_step == len(STEP_NAMES) - 1, use_container_width=True): st.session_state.viz_step += 1

        step = st.session_state.viz_step
        st.subheader(STEP_NAMES[step])

        if step == 0:
            c1, c2 = st.columns(2)
            c1.markdown(f"- **Key**: `{key.hex()}`\n- **Nonce**: `{V['nonce'].hex()}`")
            c2.markdown(f"- **Plaintext**: `{V['msg']}`")
            flow_diagram([{"label": "Key + Nonce"}, {"label": "Mesin ChaCha20"}, {"label": "Keystream"}, {"label": "XOR dgn Plaintext"}, {"label": "Ciphertext"}])
            
        elif step == 1:
            st.markdown("ChaCha20 memanipulasi matriks 4x4 berisi angka 32-bit (Konstanta, Key, Counter, Nonce).")
            st.code(grid(V["state0"]), language="text")
            
            st.markdown("**Contoh 1 Quarter Round Nyata** (XOR, Tambah, Rotasi):")
            a0, b0, c0, d0 = V["state0"][0], V["state0"][4], V["state0"][8], V["state0"][12]
            qr_rows = [{"Langkah": label, "a": val_hex(a, 8), "b": val_hex(b, 8), "c": val_hex(c, 8), "d": val_hex(d, 8)} for label, a, b, c, d in quarter_round_trace(a0, b0, c0, d0)]
            st.dataframe(pd.DataFrame(qr_rows), use_container_width=True)
            
            st.markdown("Setelah matriks diacak 20 putaran, hasilnya dijumlahkan dengan matriks awal untuk membentuk **Keystream**:")
            st.code(V["keystream1"][:32].hex() + "...", language="text")

        elif step == 2:
            st.markdown("Keystream yang dihasilkan mesin ChaCha20 di-**XOR**-kan dengan byte pesan asli.")
            tabel_xor_byte(V["pt_bytes"], V["keystream1"], V["ciphertext"], "Plaintext", "Ciphertext", char_from="a")

        elif step == 3:
            st.markdown("Dekripsi di ChaCha20 adalah **mengulangi proses enkripsi**. Ciphertext di-XOR kembali dengan Keystream yang sama.")
            tabel_xor_byte(V["ciphertext"], V["keystream1"], V["recovered"], "Ciphertext", "Plaintext", char_from="hasil")
            st.success(f"Pesan kembali: **{V['recovered'].decode(errors='replace')}**")