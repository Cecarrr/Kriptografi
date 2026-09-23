import os
import hmac
import streamlit as st
import pandas as pd
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

st.set_page_config(page_title="ChaCha20-Poly1305", page_icon="🔐", layout="wide")

# =========================================================
# BAGIAN 1: IMPLEMENTASI MANUAL RFC 8439 — KHUSUS VISUALISASI
# (tidak dipakai untuk enkripsi/dekripsi data sungguhan di tab 1 & 2)
# =========================================================

MASK32 = 0xFFFFFFFF
P1305 = (1 << 130) - 5


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = rotl(s[b], 7)


def quarter_round_trace(a: int, b: int, c: int, d: int) -> list:
    """Versi quarter_round yang mencatat setiap sub-langkah aritmatika,
    dipakai murni untuk ilustrasi 'apa yang terjadi di dalam 1 quarter round'."""
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
    nw = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 12, 4)]
    return constants + kw + [counter] + nw


def chacha20_block_with_trace(key: bytes, nonce: bytes, counter: int):
    """Hasilkan 1 blok keystream (64 byte) SAMBIL merekam matriks state
    setelah setiap double-round (untuk diperlihatkan progres difusinya)."""
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


def chacha20_encrypt_manual(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, nonce, counter + i // 64)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], block))
    return bytes(out)


def poly1305_mac_trace(key32: bytes, msg: bytes):
    """Hitung tag Poly1305 SAMBIL merekam akumulasi polinomial per blok 16-byte."""
    r = int.from_bytes(key32[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key32[16:], "little")
    acc = 0
    trace = []
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc_before = acc
        acc = (acc + n) * r % P1305
        trace.append((block, n, acc_before, acc))
    tag_val = (acc + s) & ((1 << 128) - 1)
    tag = tag_val.to_bytes(16, "little")
    return tag, r, s, trace


def poly1305_mac(key32: bytes, msg: bytes) -> bytes:
    tag, _, _, _ = poly1305_mac_trace(key32, msg)
    return tag


def pad16(x: bytes) -> bytes:
    return b"" if len(x) % 16 == 0 else b"\x00" * (16 - len(x) % 16)


def build_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad + pad16(aad) + ciphertext + pad16(ciphertext)
        + len(aad).to_bytes(8, "little") + len(ciphertext).to_bytes(8, "little")
    )


def grid(state: list) -> str:
    return "\n".join(" ".join(f"{w:08x}" for w in state[r * 4:(r + 1) * 4]) for r in range(4))


# =========================================================
# BAGIAN 1.5: HELPER EDUKASI & VISUALISASI
# (hanya untuk menjelaskan konsep di tab "Visualisasi Proses Lengkap";
#  tidak dipakai untuk enkripsi/dekripsi data sungguhan)
# =========================================================

def hex_dec(x: int, hex_width: int = 8) -> str:
    """Tampilkan satu angka dalam HEX sekaligus DESIMAL, supaya orang yang
    belum terbiasa baca hex tetap bisa mengecek/mencocokkan angkanya."""
    return f"`0x{x:0{hex_width}x}` (desimal: **{x}**)"


def flow_diagram(items: list, note: str = None):
    """Diagram alur sederhana: kotak-kotak dihubungkan panah, dibuat pakai
    HTML/CSS ringan (tanpa perlu library gambar tambahan).
    PENTING: seluruh HTML dibangun sebagai satu baris TANPA newline/indentasi,
    karena Markdown menganggap baris berawalan >=4 spasi sebagai blok kode —
    kalau tidak, sebagian diagram malah tampil sebagai teks source code mentah."""
    parts = []
    for i, it in enumerate(items):
        sub = it.get("sub", "")
        sub_html = (
            f'<div style="font-size:12px;color:#888;margin-top:6px;text-align:center;">{sub}</div>'
            if sub else ""
        )
        box = (
            '<div style="display:flex;flex-direction:column;align-items:center;max-width:150px;">'
            '<div style="background:#2b6cb0;color:#fff;border-radius:10px;padding:10px 14px;'
            f'text-align:center;font-weight:600;font-size:14px;">{it["label"]}</div>'
            f'{sub_html}</div>'
        )
        parts.append(box)
        if i < len(items) - 1:
            parts.append('<div style="font-size:24px;color:#aaa;padding:0 10px;align-self:center;">→</div>')
    html = (
        '<div style="display:flex;align-items:flex-start;justify-content:center;'
        'flex-wrap:wrap;gap:2px;padding:14px 0;">' + "".join(parts) + "</div>"
    )
    st.markdown(html, unsafe_allow_html=True)
    if note:
        st.caption(note)


def render_hexdec_crash_course():
    st.markdown(
        "Di tab ini, angka sering ditulis dalam **HEX** (basis 16) karena lebih ringkas "
        "daripada biner, dan itu yang lazim dipakai di dunia kriptografi. Supaya tidak bingung, "
        "**desimalnya selalu ditulis di sebelah hex-nya.**"
    )
    contoh = [(0, "0000"), (5, "0101"), (10, "1010"), (15, "1111"), (255, "1111 1111")]
    df = pd.DataFrame([{"Hex": f"0x{h:X}", "Desimal": h, "Biner": b} for h, b in contoh])
    st.dataframe(df, use_container_width=True)
    st.caption("1 digit hex = 4 digit biner. Jadi angka 32-bit cukup ditulis 8 digit hex saja.")


def demo_rotasi_kecil():
    st.markdown(
        "**Rotasi bit (`<<<`)** = geser semua bit ke kiri; bit yang \"jatuh\" dari ujung kiri "
        "dipasang lagi di ujung kanan (mirip jarum jam yang muter balik ke awal)."
    )
    x, n = 0b10110001, 3  # 177, hanya ilustrasi 8-bit (ChaCha20 asli pakai 32-bit)
    rotated = ((x << n) | (x >> (8 - n))) & 0xFF
    st.write(f"Contoh kecil — angka 8-bit **{x}** digeser kiri {n} bit:")
    st.code(f"Sebelum : {x:3d}  = {x:08b}\nSesudah : {rotated:3d}  = {rotated:08b}", language="text")
    st.caption("3 bit paling kiri (101) pindah ke posisi paling kanan.")


def demo_quarter_round_kecil():
    st.markdown(
        "**Quarter round** = satu paket kecil operasi (tambah `mod`, `XOR`, lalu rotasi bit) "
        "yang diulang berkali-kali untuk mengacak 4 angka (`a,b,c,d`). Contoh di bawah pakai "
        "angka 8-bit kecil supaya gampang diikuti — aslinya ChaCha20 memakai angka 32-bit dan "
        "jumlah geser (rotasi) yang berbeda (16, 12, 8, 7)."
    )
    mask = 0xFF
    a, b, c, d = 3, 7, 11, 5
    langkah = []
    a = (a + b) & mask; d ^= a; d = ((d << 4) | (d >> 4)) & mask
    langkah.append(("a += b ; d ^= a ; d diputar 4 bit", a, b, c, d))
    c = (c + d) & mask; b ^= c; b = ((b << 3) | (b >> 5)) & mask
    langkah.append(("c += d ; b ^= c ; b diputar 3 bit", a, b, c, d))
    a = (a + b) & mask; d ^= a; d = ((d << 2) | (d >> 6)) & mask
    langkah.append(("a += b ; d ^= a ; d diputar 2 bit", a, b, c, d))
    c = (c + d) & mask; b ^= c; b = ((b << 1) | (b >> 7)) & mask
    langkah.append(("c += d ; b ^= c ; b diputar 1 bit", a, b, c, d))

    rows = [{"Langkah": lbl, "a": av, "b": bv, "c": cv, "d": dv} for lbl, av, bv, cv, dv in langkah]
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    st.caption("Coba hitung sendiri baris pertama: a = 3+7 = 10, lalu d = 5 XOR 10 = 15, baru 15 diputar 4 bit.")


def demo_poly_kecil():
    st.markdown(
        "**Ide Poly1305** (versi angka kecil; angka asli tetap super besar): pesan dipecah "
        "jadi blok-blok, lalu tiap blok \"diaduk\" ke sebuah akumulator (`acc`) dengan rumus:  \n"
        "`acc_baru = (acc_lama + blok) × r  mod  p`  \n"
        "(pakai bilangan prima `p` besar supaya hasilnya sulit ditebak/dibalik)."
    )
    p_kecil, r_kecil = 97, 5
    blok_kecil = [12, 7, 30]
    acc = 0
    rows = []
    for i, b in enumerate(blok_kecil, start=1):
        before = acc
        acc = (acc + b) * r_kecil % p_kecil
        rows.append({
            "Blok ke-": i, "Nilai blok": b, "acc sebelum": before,
            "Rumus": f"({before} + {b}) × {r_kecil} mod {p_kecil}", "acc sesudah": acc,
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True)
    st.caption(
        f"Di atas pakai p={p_kecil} & r={r_kecil} (angka kecil, coba hitung sendiri pakai kalkulator!). "
        "Poly1305 asli memakai p = 2¹³⁰−5 dan r sepanjang 128-bit, supaya hampir mustahil ditebak."
    )


def val_hex(x: int, hex_width: int = 2) -> str:
    """Satu angka ditulis ringkas: desimal + hex dalam satu string,
    supaya tabel tidak perlu kolom dec & hex terpisah.
    hex_width=2 untuk byte (8-bit), hex_width=8 untuk kata (32-bit)."""
    return f"{x} (0x{x:0{hex_width}x})"


def tabel_xor_byte(bytes_a: bytes, keystream: bytes, bytes_hasil: bytes,
                    label_a: str = "Plaintext", label_hasil: str = "Ciphertext",
                    char_from: str = "a"):
    """Tabel perhitungan XOR per posisi byte — dec & hex digabung satu kolom
    per field (5 kolom total, bukan 8) supaya lebih ringkas dibaca."""
    sumber_karakter = bytes_a if char_from == "a" else bytes_hasil
    rows = []
    for i in range(len(bytes_a)):
        pa, pb, ph = bytes_a[i], keystream[i], bytes_hasil[i]
        ch_val = sumber_karakter[i]
        ch = chr(ch_val) if 32 <= ch_val <= 126 else "·"
        rows.append({
            "Posisi": i + 1,
            "Karakter": ch,
            label_a: val_hex(pa),
            "Keystream": val_hex(pb),
            label_hasil: val_hex(ph),
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, height=min(38 * (len(rows) + 1), 420))
    st.caption(
        "Format tiap angka: desimal (0xhex). XOR per posisi byte: kolom kiri "
        "di-XOR dengan Keystream pada posisi yang sama → hasil di kolom kanan."
    )


# =========================================================
# BAGIAN 2: ENKRIPSI/DEKRIPSI SESUNGGUHNYA — pakai library `cryptography`
# =========================================================

def real_encrypt(key: bytes, plaintext: bytes, aad: bytes):
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ct_with_tag = aead.encrypt(nonce, plaintext, aad if aad else None)
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return nonce, ciphertext, tag


def real_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes):
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ciphertext + tag, aad if aad else None)


# =========================================================
# BAGIAN 3: ANTARMUKA STREAMLIT
# =========================================================

st.title("ChaCha20-Poly1305")
st.caption("Algoritma kriptografi modern — AEAD (Authenticated Encryption with Associated Data)")
st.caption("Enkripsi/dekripsi memakai library `cryptography` · Visualisasi memakai implementasi manual RFC 8439")

if "key" not in st.session_state:
    st.session_state.key = os.urandom(32)

with st.sidebar:
    st.subheader("Kunci (Key)")
    key_hex = st.text_input("Key — hex, 64 karakter (32 byte)", value=st.session_state.key.hex())
    if st.button("Generate key baru"):
        st.session_state.key = os.urandom(32)
        st.rerun()
    try:
        key = bytes.fromhex(key_hex)
        assert len(key) == 32
    except (ValueError, AssertionError):
        st.error("Key harus 64 karakter hex (32 byte).")
        st.stop()

    aad_text = st.text_input("Associated Data / AAD (opsional)", value="")
    st.caption("AAD ikut diautentikasi tapi tidak dienkripsi, misal: header/metadata pesan.")

tab_enc, tab_dec, tab_proses = st.tabs(["Enkripsi", "Dekripsi", "Visualisasi Proses Lengkap"])

# ---------------------------------------------------------
# TAB ENKRIPSI (library)
# ---------------------------------------------------------
with tab_enc:
    plaintext = st.text_area("Plaintext", height=120, placeholder="Tulis pesan yang akan dienkripsi...")
    if st.button("Enkripsi", type="primary"):
        if not plaintext:
            st.warning("Plaintext tidak boleh kosong.")
        else:
            nonce, ciphertext, tag = real_encrypt(key, plaintext.encode(), aad_text.encode())
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Nonce (hex)** — klik ikon copy di pojok kanan atas kotak")
                st.code(nonce.hex(), language="text")
                st.markdown("**Ciphertext (hex)**")
                st.code(ciphertext.hex(), language="text")
            with c2:
                st.markdown("**Tag / MAC (hex, 16 byte)**")
                st.code(tag.hex(), language="text")
                st.info("Salin ketiga nilai di atas (Nonce, Ciphertext, Tag) untuk dibagikan / dipakai di tab Dekripsi.")

# ---------------------------------------------------------
# TAB DEKRIPSI (library)
# ---------------------------------------------------------
with tab_dec:
    c1, c2 = st.columns(2)
    with c1:
        nonce_in = st.text_input("Nonce (hex)")
        ct_in = st.text_area("Ciphertext (hex)", height=100)
    with c2:
        tag_in = st.text_input("Tag (hex)")

    if st.button("Dekripsi", type="primary"):
        try:
            n, c, t = bytes.fromhex(nonce_in), bytes.fromhex(ct_in), bytes.fromhex(tag_in)
            pt = real_decrypt(key, n, c, t, aad_text.encode())
            st.success("Tag valid — data asli dan tidak diubah.")
            st.markdown("**Plaintext hasil dekripsi**")
            st.code(pt.decode(errors="replace"), language="text")
        except InvalidTag:
            st.error("Gagal: Tag tidak valid — data diubah, kunci salah, atau nonce salah.")
        except Exception as e:
            st.error(f"Gagal: {e}")

# ---------------------------------------------------------
# TAB VISUALISASI PROSES LENGKAP (manual RFC 8439, wizard step-by-step)
# ---------------------------------------------------------
with tab_proses:
    st.markdown(
        "Tab ini menunjukkan **apa yang terjadi di dalam algoritma**, langkah demi langkah, "
        "dihitung manual (bukan lewat library) supaya semua angka bisa dilihat — lengkap dengan "
        "contoh angka kecil untuk konsepnya, dan hex + desimal berdampingan."
    )

    msg = st.text_area(
        "Pesan untuk divisualisasikan (maks 32 karakter — biar tetap sederhana)",
        value="Halo dunia!", height=70,
    )
    if len(msg.encode()) > 32:
        msg = msg.encode()[:32].decode(errors="ignore")
        st.caption(f"Pesan dipotong otomatis jadi 32 byte pertama: \"{msg}\" — supaya jumlah blok yang divisualisasikan tetap sedikit dan mudah diikuti.")

    if st.button("Jalankan & mulai visualisasi", type="primary"):
        if not msg:
            st.warning("Pesan tidak boleh kosong.")
        else:
            pt_bytes = msg.encode()
            aad_bytes = aad_text.encode()
            nonce = os.urandom(12)

            poly_key_block, state0, snapshots0 = chacha20_block_with_trace(key, nonce, 0)
            poly_key = poly_key_block[:32]

            keystream1 = chacha20_block(key, nonce, 1)[:len(pt_bytes)]
            ciphertext = bytes(a ^ b for a, b in zip(pt_bytes, keystream1))

            mac_data = build_mac_data(aad_bytes, ciphertext)
            tag, r, s, trace = poly1305_mac_trace(poly_key, mac_data)

            poly_key_check = chacha20_block(key, nonce, 0)[:32]
            tag_check = poly1305_mac(poly_key_check, build_mac_data(aad_bytes, ciphertext))
            cocok = hmac.compare_digest(tag, tag_check)

            recovered = bytes(a ^ b for a, b in zip(ciphertext, keystream1))

            st.session_state.viz = dict(
                msg=msg, pt_bytes=pt_bytes, aad_bytes=aad_bytes, nonce=nonce,
                state0=state0, snapshots0=snapshots0, poly_key=poly_key,
                keystream1=keystream1, ciphertext=ciphertext,
                mac_data=mac_data, tag=tag, r=r, s=s, trace=trace,
                tag_check=tag_check, cocok=cocok, recovered=recovered,
            )
            st.session_state.viz_step = 0

    if "viz" not in st.session_state:
        st.info("Isi pesan di atas lalu klik tombol **Jalankan** untuk mulai.")
    else:
        V = st.session_state.viz
        STEP_NAMES = [
            "0. Bahan & Peta Proses",
            "1. Bikin Kunci Poly1305",
            "2. Acak Pesan (ChaCha20)",
            "3. Buat Tanda Tangan (Poly1305)",
            "4. Hasil Akhir Enkripsi",
            "5. Dekripsi: Cek & Buka Pesan",
        ]
        if "viz_step" not in st.session_state:
            st.session_state.viz_step = 0

        st.divider()
        nav1, nav2, nav3 = st.columns([1, 3, 1])
        with nav1:
            if st.button("⬅ Sebelumnya", disabled=st.session_state.viz_step == 0, use_container_width=True):
                st.session_state.viz_step -= 1
        with nav2:
            pilih = st.selectbox("Lompat ke langkah", STEP_NAMES, index=st.session_state.viz_step)
            st.session_state.viz_step = STEP_NAMES.index(pilih)
        with nav3:
            if st.button("Selanjutnya ➡", disabled=st.session_state.viz_step == len(STEP_NAMES) - 1, use_container_width=True):
                st.session_state.viz_step += 1

        step = st.session_state.viz_step
        st.subheader(STEP_NAMES[step])

        # ---------------- STEP 0 : Bahan & Peta Proses ----------------
        if step == 0:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown(f"- **Key** (kunci rahasia): `{key.hex()}`")
                st.markdown(f"- **Nonce** (nomor sekali pakai, dibuat acak): `{V['nonce'].hex()}`")
            with c2:
                st.markdown(f"- **AAD** (data tambahan yang ikut diverifikasi): `{V['aad_bytes'].decode(errors='replace') or '(kosong)'}`")
                st.markdown(f"- **Plaintext** (pesan asli): `{V['msg']}` — {len(V['pt_bytes'])} byte")
            st.caption(
                "Analogi: Key = kunci rumah, Nonce = nomor seri sekali pakai supaya kunci yang sama "
                "tidak pernah menghasilkan pola yang sama dua kali, AAD = label paket yang boleh dibaca "
                "semua orang tapi tetap ikut dicek keasliannya."
            )
            st.markdown("**Peta proses secara garis besar:**")
            flow_diagram([
                {"label": "Key + Nonce", "sub": "bahan rahasia"},
                {"label": "Mesin ChaCha20", "sub": "\"pengacak\" angka"},
                {"label": "Keystream", "sub": "angka acak sepanjang pesan"},
                {"label": "XOR dgn Plaintext", "sub": "operasi yang sudah familiar"},
                {"label": "Ciphertext", "sub": "pesan tersamar"},
            ])
            flow_diagram([
                {"label": "Ciphertext + AAD", "sub": ""},
                {"label": "Mesin Poly1305", "sub": "\"penanda-tangan\""},
                {"label": "Tag", "sub": "bukti pesan tidak diubah"},
            ])
            with st.expander("Belum terbiasa baca HEX? Buka dulu di sini"):
                render_hexdec_crash_course()

        # ---------------- STEP 1 : Kunci Poly1305 (ChaCha20) ----------------
        elif step == 1:
            st.markdown(
                "ChaCha20 bekerja seperti **mesin pengacak angka**: diberi Key + Nonce + sebuah "
                "\"nomor hitung\" (counter), mesin ini menghasilkan 64 byte angka acak (**keystream**). "
                "Langkah pertama: pakai counter = 0 untuk menghasilkan kunci khusus bagi Poly1305 nanti."
            )
            with st.expander("Konsep: rotasi bit (operasi baru yang dipakai di sini)"):
                demo_rotasi_kecil()
            with st.expander("Konsep: 1 'quarter round' dengan angka kecil"):
                demo_quarter_round_kecil()

            st.markdown("**Sekarang dengan angka sungguhan.** Matriks awal (16 angka 32-bit):")
            st.code(grid(V["state0"]), language="text")
            st.caption("4 baris = 4 konstanta tetap, 8 kata kunci, 1 counter, 3 kata nonce.")

            a0, b0, c0, d0 = V["state0"][0], V["state0"][4], V["state0"][8], V["state0"][12]
            st.markdown("**Contoh 1 quarter round nyata** (mengambil posisi 0, 4, 8, 12 dari matriks di atas):")
            st.caption(f"Awal: a={val_hex(a0, 8)}, b={val_hex(b0, 8)}, c={val_hex(c0, 8)}, d={val_hex(d0, 8)}")
            qr_rows = [
                {"Langkah": label, "a": val_hex(a, 8), "b": val_hex(b, 8), "c": val_hex(c, 8), "d": val_hex(d, 8)}
                for label, a, b, c, d in quarter_round_trace(a0, b0, c0, d0)
            ]
            st.dataframe(pd.DataFrame(qr_rows), use_container_width=True)

            st.markdown(
                "**Pola di atas (1 quarter round) diulang 8× untuk membentuk 1 'double round', lalu "
                "double round itu diulang 10× (total 20 round / 80 quarter round).** Kita lewati "
                "detail round 2 sampai 10 karena polanya sama persis, cuma angkanya beda — "
                "berikut perbandingan sebelum vs sesudah semuanya selesai:"
            )
            cA, cB = st.columns(2)
            with cA:
                st.markdown("*Sebelum (matriks awal)*")
                st.code(grid(V["state0"]), language="text")
            with cB:
                st.markdown("*Sesudah 20 round*")
                st.code(grid(V["snapshots0"][-1]), language="text")
            st.caption("Perhatikan betapa berbedanya — itulah tujuan 'pengacakan': dari angka yang mudah ditebak jadi terlihat acak total.")

            st.markdown("**Hasil akhir**: output 20-round dijumlahkan lagi ke matriks awal (feed-forward), lalu 32 byte pertamanya dipakai sebagai kunci khusus Poly1305:")
            st.code(V["poly_key"].hex(), language="text")

        # ---------------- STEP 2 : Enkripsi ChaCha20 (XOR) ----------------
        elif step == 2:
            st.markdown(
                "Mesin ChaCha20 dijalankan lagi dengan **counter = 1** untuk menghasilkan keystream "
                "baru. Keystream ini di-**XOR**-kan dengan pesan asli, byte demi byte — operasi yang "
                "sama dengan yang mungkin sudah Anda kenal."
            )
            flow_diagram([
                {"label": "Plaintext", "sub": "pesan asli"},
                {"label": "XOR", "sub": "⊕"},
                {"label": "Ciphertext", "sub": "pesan tersamar"},
            ])
            st.markdown("**Perhitungan per byte** (bisa dicek satu per satu):")
            tabel_xor_byte(V["pt_bytes"], V["keystream1"], V["ciphertext"],
                           "Plaintext", "Ciphertext", char_from="a")
            st.caption(
                "Kenapa aman untuk di-XOR balik? Karena XOR itu reversibel: "
                "Ciphertext ⊕ Keystream = Plaintext lagi (dipakai nanti saat dekripsi)."
            )

        # ---------------- STEP 3 : Tag Poly1305 ----------------
        elif step == 3:
            st.markdown(
                "Poly1305 membuat sebuah **tanda tangan pendek (tag, 16 byte)** dari seluruh pesan, "
                "supaya penerima tahu kalau pesan/AAD sedikit saja diubah — tag-nya pasti berubah total."
            )
            with st.expander("Konsep: bagaimana 'tanda tangan' ini dihitung (angka kecil)"):
                demo_poly_kecil()

            st.markdown("**Data yang ditandatangani** = AAD + padding + Ciphertext + padding + panjang AAD & Ciphertext:")
            st.code(V["mac_data"].hex(), language="text")

            r, s, trace = V["r"], V["s"], V["trace"]
            st.write(f"Parameter rahasia: r = {hex_dec(r, 32)}, s = {hex_dec(s, 32)}")
            st.caption("r dan s berasal dari kunci Poly1305 di Langkah 1 — sangat besar (128-bit) supaya sulit ditebak.")

            n_show = min(2, len(trace))
            for i in range(n_show):
                block, n_val, acc_before, acc_after = trace[i]
                st.markdown(f"*Blok ke-{i + 1} dari {len(trace)}* — data: `{block.hex()}`")
                st.write(f"- n (blok + penanda) = {hex_dec(n_val, 34)}")
                st.write(f"- acc sebelum = {hex_dec(acc_before, 34)}")
                st.write(f"- acc sesudah = (acc + n) × r mod (2¹³⁰−5) = {hex_dec(acc_after, 34)}")
            if len(trace) > n_show:
                st.caption(f"... {len(trace) - n_show} blok berikutnya memakai rumus & pola yang sama persis, cuma datanya beda.")

            st.markdown("**Tag akhir** = (acc terakhir + s) mod 2¹²⁸:")
            st.code(V["tag"].hex(), language="text")

        # ---------------- STEP 4 : Hasil Akhir Enkripsi ----------------
        elif step == 4:
            st.markdown("Ini yang akan dikirim/disimpan — cukup 3 hal ini untuk bisa dibuka kembali nanti:")
            st.code(
                f"Nonce      : {V['nonce'].hex()}\nCiphertext : {V['ciphertext'].hex()}\nTag        : {V['tag'].hex()}",
                language="text",
            )
            st.caption("Key TIDAK ikut dikirim — itu tetap rahasia di kedua pihak.")

        # ---------------- STEP 5 : Dekripsi (verifikasi + buka pesan) ----------------
        elif step == 5:
            st.markdown("**5a. Cek keaslian dulu** — hitung ulang tag dari Ciphertext yang diterima, lalu bandingkan:")
            st.code(f"Tag diterima      : {V['tag'].hex()}\nTag dihitung ulang: {V['tag_check'].hex()}", language="text")
            if V["cocok"]:
                st.success("Cocok - pesan terbukti asli & tidak diubah. Lanjut buka pesan.")
            else:
                st.error("Tidak cocok - di sistem nyata proses akan dihentikan di sini (pesan ditolak).")

            st.markdown("**5b. Buka pesan** — XOR lagi Ciphertext dengan keystream yang sama (counter = 1):")
            flow_diagram([
                {"label": "Ciphertext"},
                {"label": "XOR", "sub": "⊕ (keystream sama)"},
                {"label": "Plaintext", "sub": "pesan asli kembali"},
            ])
            tabel_xor_byte(V["ciphertext"], V["keystream1"], V["recovered"],
                           "Ciphertext", "Plaintext", char_from="hasil")
            st.success(f"Pesan berhasil dibuka: **{V['recovered'].decode(errors='replace')}**")