import streamlit as st
import pandas as pd
import hashlib
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

st.set_page_config(page_title="AES-128 Kriptografi", page_icon="🔐", layout="wide")

# =========================================================
# BAGIAN 1: TABEL & FUNGSI MANUAL AES (KHUSUS VISUALISASI)
# =========================================================

# Tabel S-Box standar AES (untuk tahap SubBytes)
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

def byte_to_matrix(data_bytes):
    """Mengubah 16 byte menjadi matriks 4x4 (Column-major order khas AES)"""
    return [[data_bytes[r + 4 * c] for c in range(4)] for r in range(4)]

def format_matrix(matrix):
    """Menampilkan matriks 4x4 dalam format Hex"""
    res = ""
    for r in range(4):
        res += " ".join([f"{matrix[r][c]:02x}" for c in range(4)]) + "\n"
    return res

def add_round_key(state, key_matrix):
    return [[state[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]

def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state):
    # Baris 0: tidak digeser
    # Baris 1: geser kiri 1
    # Baris 2: geser kiri 2
    # Baris 3: geser kiri 3
    new_state = [row[:] for row in state]
    new_state[1] = new_state[1][1:] + new_state[1][:1]
    new_state[2] = new_state[2][2:] + new_state[2][:2]
    new_state[3] = new_state[3][3:] + new_state[3][:3]
    return new_state

# =========================================================
# BAGIAN 1.5: HELPER EDUKASI & VISUALISASI UI
# =========================================================

def flow_diagram(items):
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

# =========================================================
# BAGIAN 2: ENKRIPSI/DEKRIPSI ASLI (PyCryptodome)
# =========================================================

def get_aes_key(master_password):
    return hashlib.md5(master_password.encode('utf-8')).digest()

def aes_encrypt(plaintext, password):
    key = get_aes_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    pt_padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(pt_padded)
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext_b64, password):
    key = get_aes_key(password)
    raw_data = base64.b64decode(ciphertext_b64)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ciphertext)
    return unpad(pt_padded, AES.block_size).decode('utf-8')

# =========================================================
# BAGIAN 3: ANTARMUKA STREAMLIT
# =========================================================

st.title("AES-128 (Advanced Encryption Standard)")
st.caption("Algoritma kriptografi modern (Block Cipher)")

with st.sidebar:
    st.subheader("Konfigurasi Kunci Utama")
    st.markdown("Karena ini Super Enkripsi, kita men-simulasikan 1 kunci untuk 4 menu. Master password ini akan di-*hash* dengan MD5 agar mutlak menjadi 16-byte untuk AES.")
    master_key = st.text_input("Master Password", value="RAHASIA", type="password")
    key_16 = get_aes_key(master_key)
    st.markdown(f"**Key AES (16-Byte Hex):**\n`{key_16.hex()}`")

tab_enc, tab_dec, tab_proses = st.tabs(["Enkripsi", "Dekripsi", "Visualisasi Proses Lengkap"])

# --- TAB ENKRIPSI ---
with tab_enc:
    plaintext = st.text_area("Plaintext", placeholder="Masukkan pesan rahasia...")
    if st.button("Enkripsi Data", type="primary"):
        if not plaintext:
            st.warning("Plaintext tidak boleh kosong.")
        else:
            hasil_b64 = aes_encrypt(plaintext, master_key)
            st.success("Enkripsi Berhasil!")
            st.markdown("**Hasil Akhir (Base64) - Kirim ini ke algoritma selanjutnya:**")
            st.code(hasil_b64, language="text")

# --- TAB DEKRIPSI ---
with tab_dec:
    ciphertext_in = st.text_area("Ciphertext (Base64)", placeholder="Masukkan ciphertext dari menu sebelumnya...")
    if st.button("Dekripsi Data", type="primary"):
        try:
            pt = aes_decrypt(ciphertext_in, master_key)
            st.success("Dekripsi Berhasil!")
            st.markdown("**Plaintext hasil dekripsi:**")
            st.code(pt, language="text")
        except Exception as e:
            st.error(f"Gagal dekripsi. Data korup, padding salah, atau kunci salah! ({e})")

# --- TAB VISUALISASI MANUAL ---
with tab_proses:
    st.markdown("Tab ini membedah anatomi 1 Blok AES (16 byte pertama) langkah-demi-langkah.")
    
    msg = st.text_area("Pesan untuk divisualisasikan (maks 16 karakter)", value="Halo Dunia 123!", height=70)
    if len(msg.encode()) > 16:
        msg = msg.encode()[:16].decode(errors="ignore")
        st.caption(f"Pesan dipotong otomatis jadi 16 byte (1 blok): \"{msg}\"")
        
    if st.button("Jalankan Visualisasi AES"):
        pt_bytes = pad(msg.encode(), 16)[:16]
        
        # Inisialisasi Matriks
        state_matrix = byte_to_matrix(pt_bytes)
        key_matrix = byte_to_matrix(key_16)
        
        st.subheader("0. Persiapan Matriks (State)")
        st.write("AES bekerja dengan menyusun 16 byte data ke dalam matriks 4x4 (dari atas ke bawah, lalu ke kanan).")
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Matriks Plaintext (Hex)**")
            st.code(format_matrix(state_matrix), language="text")
        with c2:
            st.markdown("**Matriks Kunci (Hex)**")
            st.code(format_matrix(key_matrix), language="text")
            
        st.divider()
        st.subheader("1. Initial AddRoundKey (XOR)")
        st.write("Langkah pertama: Matriks Plaintext di-XOR dengan Matriks Kunci.")
        
        state_after_ark = add_round_key(state_matrix, key_matrix)
        st.code(format_matrix(state_after_ark), language="text")
        
        st.divider()
        st.subheader("2. Ronde 1: SubBytes (Substitusi)")
        st.write("Setiap byte pada matriks dicocokkan dengan tabel **S-Box** AES. Proses ini memecah pola linearistik pesan (Confusion).")
        
        state_after_sub = sub_bytes(state_after_ark)
        c1, c2 = st.columns(2)
        c1.markdown("*Sebelum SubBytes:*")
        c1.code(format_matrix(state_after_ark), language="text")
        c2.markdown("*Sesudah SubBytes:*")
        c2.code(format_matrix(state_after_sub), language="text")
        
        st.divider()
        st.subheader("3. Ronde 1: ShiftRows (Pergeseran)")
        st.write("Baris pertama matriks diam. Baris ke-2 digeser ke kiri 1 langkah. Baris ke-3 digeser 2 langkah, dst. (Diffusion).")
        
        state_after_shift = shift_rows(state_after_sub)
        c1, c2 = st.columns(2)
        c1.markdown("*Sebelum ShiftRows:*")
        c1.code(format_matrix(state_after_sub), language="text")
        c2.markdown("*Sesudah ShiftRows:*")
        c2.code(format_matrix(state_after_shift), language="text")

        st.divider()
        st.subheader("4. Ronde 1: MixColumns (Perkalian Galois Field)")
        st.warning("Perhatian: Tidak seperti algoritma klasik atau ChaCha20, tahap ini melibatkan perkalian matriks menggunakan Polinomial di Galois Field $GF(2^8)$.")
        
        st.write("Setiap kolom dalam state dikalikan dengan matriks polinomial konstan. Hasilnya akan mengacak data lebih jauh lagi:")
        flow_diagram([
            {"label": "State Kolom 1"},
            {"label": "Matriks GF(2^8)", "sub": "Di-XOR dan dikalikan"},
            {"label": "Kolom Teracak"}
        ])
        st.info("Karena ini adalah 1 ronde dari total 10 ronde, langkah SubBytes hingga AddRoundKey akan terus diulang 9 kali lagi (di kode produksi) dengan kunci yang telah di-expand.")