import streamlit as st
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

st.set_page_config(page_title="Modul AES-128", layout="wide")

# =========================================================
# BAGIAN 1: TABEL & FUNGSI MANUAL AES (KHUSUS VISUALISASI)
# =========================================================

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
    return [[data_bytes[r + 4 * c] for c in range(4)] for r in range(4)]

def format_matrix(matrix):
    res = ""
    for r in range(4):
        res += " ".join([f"{matrix[r][c]:02x}" for c in range(4)]) + "\n"
    return res

def add_round_key(state, key_matrix):
    return [[state[r][c] ^ key_matrix[r][c] for c in range(4)] for r in range(4)]

def sub_bytes(state):
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def shift_rows(state):
    new_state = [row[:] for row in state]
    new_state[1] = new_state[1][1:] + new_state[1][:1]
    new_state[2] = new_state[2][2:] + new_state[2][:2]
    new_state[3] = new_state[3][3:] + new_state[3][:3]
    return new_state

# =========================================================
# BAGIAN 2: ENKRIPSI/DEKRIPSI ASLI (PyCryptodome)
# =========================================================

def get_aes_key(password):
    # AES-128 mutlak butuh kunci 16-byte. Kita hash input user agar selalu pas 16-byte.
    return hashlib.md5(password.encode('utf-8')).digest()

def aes_encrypt(plaintext, password):
    key = get_aes_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    pt_padded = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(pt_padded)
    # Output berupa Hex string (IV + Ciphertext digabung)
    return (iv + ciphertext).hex()

def aes_decrypt(ciphertext_hex, password):
    key = get_aes_key(password)
    raw_data = bytes.fromhex(ciphertext_hex)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ciphertext)
    return unpad(pt_padded, AES.block_size).decode('utf-8')

# =========================================================
# BAGIAN 3: ANTARMUKA STREAMLIT
# =========================================================

st.title("AES-128 Encryption & Decryption")
st.caption("Aplikasi Standalone AES-128 dengan Visualisasi Proses Blok (Mode CBC)")

with st.sidebar:
    st.subheader("Konfigurasi Kunci (Key)")
    st.markdown("AES-128 membutuhkan kunci tepat **16 Byte (128 bit)**. Untuk kemudahan, password yang Anda masukkan akan diproses dengan *hashing* MD5 sehingga ukurannya selalu pas 16 Byte.")
    user_password = st.text_input("Masukkan Password", value="Rahasia123", type="password")
    key_16 = get_aes_key(user_password)
    st.markdown(f"**Kunci Aktual AES (Hex):**\n`{key_16.hex()}`")

tab_enc, tab_dec, tab_proses = st.tabs(["Enkripsi", "Dekripsi", "Visualisasi Proses Blok"])

# --- TAB ENKRIPSI ---
with tab_enc:
    st.subheader("Enkripsi Pesan")
    plaintext = st.text_area("Plaintext", placeholder="Masukkan pesan rahasia yang ingin dienkripsi...")
    if st.button("Enkripsi Data", type="primary"):
        if not plaintext:
            st.warning("Plaintext tidak boleh kosong.")
        else:
            hasil_hex = aes_encrypt(plaintext, user_password)
            st.success("Enkripsi Berhasil!")
            st.markdown("**Hasil Ciphertext (Hex):**")
            st.code(hasil_hex, language="text")
            st.caption("*Catatan: 16 byte pertama dari ciphertext ini adalah IV (Initialization Vector).*")

# --- TAB DEKRIPSI ---
with tab_dec:
    st.subheader("Dekripsi Pesan")
    ciphertext_in = st.text_area("Ciphertext (Hex)", placeholder="Masukkan string hex dari hasil enkripsi...")
    if st.button("Dekripsi Data", type="primary"):
        try:
            pt = aes_decrypt(ciphertext_in.strip(), user_password)
            st.success("Dekripsi Berhasil!")
            st.markdown("**Plaintext hasil dekripsi:**")
            st.code(pt, language="text")
        except ValueError:
            st.error("Gagal dekripsi. Format Hex tidak valid, Padding salah, atau Kunci salah!")
        except Exception as e:
            st.error(f"Terjadi kesalahan: {e}")

# --- TAB VISUALISASI MANUAL ---
with tab_proses:
    st.markdown("Tab ini memvisualisasikan bagaimana AES memproses **16 byte pertama** (1 blok) dari pesan Anda pada tahap awal algoritma.")
    
    msg = st.text_area("Pesan untuk divisualisasikan (maks 16 karakter)", value="Halo AES 128 bit", height=70)
    if len(msg.encode('utf-8')) > 16:
        msg = msg.encode('utf-8')[:16].decode(errors="ignore")
        st.caption(f"Pesan dipotong otomatis jadi 16 byte (1 blok): \"{msg}\"")
        
    if st.button("Jalankan Visualisasi 1 Blok"):
        pt_bytes = pad(msg.encode('utf-8'), 16)[:16]
        
        state_matrix = byte_to_matrix(pt_bytes)
        key_matrix = byte_to_matrix(key_16)
        
        st.subheader("0. Persiapan Matriks (State Matrix)")
        st.write("16 byte teks dan 16 byte kunci disusun ke dalam matriks 4x4 (dari atas ke bawah, lalu ke kanan).")
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Matriks Plaintext (Hex)**")
            st.code(format_matrix(state_matrix), language="text")
        with c2:
            st.markdown("**Matriks Kunci (Hex)**")
            st.code(format_matrix(key_matrix), language="text")
            
        st.divider()
        st.subheader("1. Initial AddRoundKey (XOR)")
        st.write("Matriks Plaintext di-XOR dengan Matriks Kunci secara posisi per posisi.")
        
        state_after_ark = add_round_key(state_matrix, key_matrix)
        st.code(format_matrix(state_after_ark), language="text")
        
        st.divider()
        st.subheader("2. Ronde 1: SubBytes (Substitusi S-Box)")
        st.write("Setiap byte hasil XOR ditukar dengan nilai baru menggunakan tabel standar *S-Box* AES.")
        
        state_after_sub = sub_bytes(state_after_ark)
        c3, c4 = st.columns(2)
        c3.markdown("*Sebelum SubBytes:*")
        c3.code(format_matrix(state_after_ark), language="text")
        c4.markdown("*Sesudah SubBytes:*")
        c4.code(format_matrix(state_after_sub), language="text")
        
        st.divider()
        st.subheader("3. Ronde 1: ShiftRows (Pergeseran Baris)")
        st.write("Baris 1 diam. Baris 2 geser kiri 1x. Baris 3 geser kiri 2x. Baris 4 geser kiri 3x.")
        
        state_after_shift = shift_rows(state_after_sub)
        c5, c6 = st.columns(2)
        c5.markdown("*Sebelum ShiftRows:*")
        c5.code(format_matrix(state_after_sub), language="text")
        c6.markdown("*Sesudah ShiftRows:*")
        c6.code(format_matrix(state_after_shift), language="text")

        st.info("Setelah tahap ini, proses berlanjut ke MixColumns (perkalian matriks Galois Field). Siklus SubBytes -> ShiftRows -> MixColumns -> AddRoundKey ini diulang sebanyak 10 kali untuk AES-128.")