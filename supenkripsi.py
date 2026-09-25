import streamlit as st
import hashlib
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad

st.set_page_config(page_title="Menu 5: Super Enkripsi", page_icon="🔗", layout="wide")

# ==========================================
# FUNGSI KEY DERIVATION (1 KUNCI UNTUK SEMUA)
# ==========================================
def derive_keys(master_password):
    # 1. Kunci Caesar: Jumlah ASCII dari password di-modulo 26
    caesar_key = sum(ord(c) for c in master_password) % 26
    
    # 2. Kunci Rail Fence: Membutuhkan angka (jumlah baris). 
    # Kita ambil dari panjang password. Minimal harus 2 baris agar algoritma bekerja.
    rail_key = max(2, (len(master_password) % 8) + 2) 
    
    # 3. Kunci ChaCha20: SHA-256 (32 Byte)
    chacha_key = hashlib.sha256(master_password.encode('utf-8')).digest()
    
    # 4. Kunci AES-128: MD5 (16 Byte)
    aes_key = hashlib.md5(master_password.encode('utf-8')).digest()
    
    return caesar_key, rail_key, chacha_key, aes_key

# ==========================================
# 1. ALGORITMA CAESAR CIPHER
# ==========================================
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# ==========================================
# 2. ALGORITMA RAIL FENCE CIPHER
# ==========================================
def railfence_encrypt(text, key):
    rail = [['\n' for i in range(len(text))] for j in range(key)]
    dir_down = False
    row, col = 0, 0
    
    for i in range(len(text)):
        if (row == 0) or (row == key - 1):
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        if dir_down: row += 1
        else: row -= 1
        
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return "".join(result)

def railfence_decrypt(cipher, key):
    rail = [['\n' for i in range(len(cipher))] for j in range(key)]
    dir_down = None
    row, col = 0, 0
    
    for i in range(len(cipher)):
        if row == 0: dir_down = True
        if row == key - 1: dir_down = False
        rail[row][col] = '*'
        col += 1
        if dir_down: row += 1
        else: row -= 1
        
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if (rail[i][j] == '*') and (index < len(cipher)):
                rail[i][j] = cipher[index]
                index += 1
                
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0: dir_down = True
        if row == key - 1: dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        if dir_down: row += 1
        else: row -= 1
    return "".join(result)

# ==========================================
# 3. ALGORITMA CHACHA20
# ==========================================
def chacha20_encrypt(text, key_32):
    cipher = ChaCha20.new(key=key_32)
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    return (cipher.nonce + ciphertext).hex()

def chacha20_decrypt(hex_data, key_32):
    raw_data = bytes.fromhex(hex_data)
    nonce, ciphertext = raw_data[:8], raw_data[8:]
    cipher = ChaCha20.new(key=key_32, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# ==========================================
# 4. ALGORITMA AES-128
# ==========================================
def aes_encrypt(text, key_16):
    cipher = AES.new(key_16, AES.MODE_CBC)
    pt_padded = pad(text.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(pt_padded)
    return (cipher.iv + ciphertext).hex()

def aes_decrypt(hex_data, key_16):
    raw_data = bytes.fromhex(hex_data)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = AES.new(key_16, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ciphertext)
    return unpad(pt_padded, AES.block_size).decode('utf-8')

# ==========================================
# UI STREAMLIT SUPER ENKRIPSI
# ==========================================
st.title("Menu 5: Super Enkripsi (Kombinasi 4 Algoritma)")
st.markdown("Alur Transmisi: **Caesar (Substitusi) ➡ Rail Fence (Transposisi) ➡ ChaCha20 (Stream) ➡ AES-128 (Block)**")

master_pwd = st.text_input("Master Password (1 Kunci untuk Semua)", value="RAHASIA123", type="password")
k_ca, k_rf, k_ch, k_ae = derive_keys(master_pwd)

with st.expander("Inspeksi Distribusi Kunci (Key Derivation)", expanded=False):
    st.write(f"- **Kunci Caesar (Int):** `{k_ca}` (Geser {k_ca} huruf)")
    st.write(f"- **Kunci Rail Fence (Int):** `{k_rf}` (Dibagi menjadi {k_rf} baris zig-zag)")
    st.write(f"- **Kunci ChaCha20 (Hex 32-byte):** `{k_ch.hex()}`")
    st.write(f"- **Kunci AES-128 (Hex 16-byte):** `{k_ae.hex()}`")

tab1, tab2 = st.tabs(["Proses Super Enkripsi", "Proses Super Dekripsi"])

with tab1:
    plaintext = st.text_area("Masukkan Plaintext")
    if st.button("Eksekusi Enkripsi", type="primary"):
        if plaintext:
            st.subheader("Trace Eksekusi Enkripsi:")
            
            res_ca = caesar_encrypt(plaintext, k_ca)
            st.markdown("**1. Output Caesar Cipher:**")
            st.code(res_ca, language="text")
            
            res_rf = railfence_encrypt(res_ca, k_rf)
            st.markdown("**2. Output Rail Fence Cipher:**")
            st.code(res_rf, language="text")
            
            res_ch = chacha20_encrypt(res_rf, k_ch)
            st.markdown("**3. Output ChaCha20 (Hex):**")
            st.code(res_ch, language="text")
            
            res_ae = aes_encrypt(res_ch, k_ae)
            st.markdown("**4. Final Output AES-128 (Super Ciphertext):**")
            st.code(res_ae, language="text")
            
            st.success("Enkripsi Berantai Selesai. Simpan Final Output untuk pengujian dekripsi.")
        else:
            st.warning("Plaintext tidak boleh kosong.")

with tab2:
    ciphertext_in = st.text_area("Masukkan Super Ciphertext (String Hex)")
    if st.button("Eksekusi Dekripsi", type="primary"):
        if ciphertext_in:
            try:
                st.subheader("Trace Eksekusi Dekripsi (Mundur):")
                
                dec_ae = aes_decrypt(ciphertext_in.strip(), k_ae)
                st.markdown("**1. Dekripsi AES-128 (Recover ChaCha20 Hex):**")
                st.code(dec_ae, language="text")
                
                dec_ch = chacha20_decrypt(dec_ae, k_ch)
                st.markdown("**2. Dekripsi ChaCha20 (Recover Teks Rail Fence):**")
                st.code(dec_ch, language="text")
                
                dec_rf = railfence_decrypt(dec_ch, k_rf)
                st.markdown("**3. Dekripsi Rail Fence (Recover Teks Caesar):**")
                st.code(dec_rf, language="text")
                
                dec_ca = caesar_decrypt(dec_rf, k_ca)
                st.markdown("**4. Final Output (Plaintext Asli):**")
                st.code(dec_ca, language="text")
                
                st.success("Dekripsi Berantai Berhasil mengembalikan pesan asli.")
            except Exception as e:
                st.error(f"Kegagalan Dekripsi. Pastikan ciphertext utuh dan password benar. Detail Error: {e}")
        else:
            st.warning("Ciphertext tidak boleh kosong.")