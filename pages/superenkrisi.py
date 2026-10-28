import streamlit as st
import pandas as pd
from crypto_engine import (
    caesar_encrypt_core, caesar_decrypt_core,
    railfence_encrypt_core, railfence_decrypt_core,
    chacha20_encrypt_core, chacha20_decrypt_core,
    aes_encrypt_core, aes_decrypt_core,
    derive_keys
)

st.set_page_config(page_title="Super Enkripsi", layout="wide")

# ==========================================
# FUNGSI HELPER UNTUK VISUALISASI UI
# ==========================================

def trace_caesar(text, shift):
    """Membuat tabel trace per karakter untuk Caesar"""
    trace_data = []
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            p = ord(char) - base
            v = (p + shift) % 26
            res = chr(v + base)
            trace_data.append({
                "Karakter": char,
                "Nilai Asli": p,
                "Rumus Modulo": f"({p} + {shift}) mod 26 = {v}",
                "Hasil Sub": res
            })
        else:
            trace_data.append({
                "Karakter": char,
                "Nilai Asli": "-",
                "Rumus Modulo": "Abaikan (Bukan Huruf)",
                "Hasil Sub": char
            })
    return pd.DataFrame(trace_data)

def trace_railfence_grid(text, key):
    """Menggambar matriks zig-zag Rail Fence di layar"""
    if key < 2: return text
    rail = [['·' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0
    for i in range(len(text)):
        if (row == 0) or (row == key - 1): 
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        row += 1 if dir_down else -1
    
    grid_str = ""
    for r in rail:
        grid_str += "  ".join(r) + "\n"
    return grid_str

# ==========================================
# ANTARMUKA SUPER ENKRIPSI
# ==========================================

st.title("Menu 5: Super Enkripsi Terintegrasi")
st.write("Alur Transmisi: Caesar -> Rail Fence -> ChaCha20 -> AES-128")

master_pwd = st.text_input("Master Password", value="RAHASIA", type="password")
k_ca, k_rf, k_ch, k_ae = derive_keys(master_pwd)

with st.expander("Inspeksi Penurunan Kunci (Key Derivation)", expanded=False):
    st.write(f"- **Caesar Shift (Int):** `{k_ca}` (Dari ASCII mod 26)")
    st.write(f"- **Rail Fence Rails (Int):** `{k_rf}` baris (Dari panjang password mod 8 + 2)")
    st.write(f"- **ChaCha20 Key (Hex):** `{k_ch.hex()}` (Dari SHA-256)")
    st.write(f"- **AES-128 Key (Hex):** `{k_ae.hex()}` (Dari MD5)")

tab_enc, tab_dec = st.tabs(["Super Enkripsi", "Super Dekripsi"])

# --- TAB ENKRIPSI ---
with tab_enc:
    plaintext = st.text_area("Masukkan Plaintext (Teks Asli)")
    
    if st.button("Jalankan Super Enkripsi", type="primary") and plaintext:
        st.divider()
        st.subheader("Trace Eksekusi Langkah demi Langkah")
        
        # 1. CAESAR CIPHER
        st.markdown("### 1. Tahap Substitusi Klasik (Caesar Cipher)")
        r1 = caesar_encrypt_core(plaintext, k_ca)
        st.dataframe(trace_caesar(plaintext, k_ca), use_container_width=True)
        st.write("**Output Caesar:**", f"`{r1}`")
        
        # 2. RAIL FENCE CIPHER
        st.markdown("### 2. Tahap Transposisi Klasik (Rail Fence Cipher)")
        r2 = railfence_encrypt_core(r1, k_rf)
        st.write("Visualisasi Matriks Zig-Zag:")
        st.code(trace_railfence_grid(r1, k_rf), language="text")
        st.write("**Output Rail Fence:**", f"`{r2}`")
        
        # 3. CHACHA20
        st.markdown("### 3. Tahap Pengacakan Stream (ChaCha20)")
        st.write("Teks dari Rail Fence diubah menjadi urutan Byte, lalu di-XOR dengan Keystream ChaCha20, menghasilkan Heksadesimal.")
        r3 = chacha20_encrypt_core(r2, k_ch)
        
        # Pembedahan sebagian (16 karakter pertama) untuk bukti visual
        sample_len = min(16, len(r2))
        pt_hex = r2[:sample_len].encode('utf-8').hex()
        st.write(f"- Potongan Plaintext Hex (Maks 16 byte): `{pt_hex}`")
        st.write(f"- Hasil Ciphertext ChaCha20 Hex (termasuk Nonce): `{r3[:50]}...`")
        st.write("**Output Lengkap ChaCha20:**", f"`{r3}`")
        
        # 4. AES-128
        st.markdown("### 4. Tahap Pemblokiran Akhir (AES-128)")
        st.write("String Heksadesimal dari ChaCha20 dipotong menjadi blok 16-byte, di-padding PKCS7, lalu di-substitusi dan diacak kolomnya (MixColumns).")
        r4 = aes_encrypt_core(r3, k_ae)
        st.write("**Output Final (Super Ciphertext):**")
        st.code(r4, language="text")

# --- TAB DEKRIPSI ---
with tab_dec:
    ciphertext_in = st.text_area("Masukkan Super Ciphertext (Hex)")
    
    if st.button("Jalankan Super Dekripsi", type="primary") and ciphertext_in:
        try:
            st.divider()
            st.subheader("Trace Reverse Engineering (Mundur)")
            
            d1 = aes_decrypt_core(ciphertext_in.strip(), k_ae)
            st.write("**1. Dekripsi AES-128 (Mendapatkan Hex ChaCha20):**")
            st.code(d1, language="text")
            
            d2 = chacha20_decrypt_core(d1, k_ch)
            st.write("**2. Dekripsi ChaCha20 (Mendapatkan Teks Rail Fence):**")
            st.code(d2, language="text")
            
            d3 = railfence_decrypt_core(d2, k_rf)
            st.write("**3. Dekripsi Rail Fence (Mendapatkan Teks Caesar):**")
            st.code(d3, language="text")
            
            d4 = caesar_decrypt_core(d3, k_ca)
            st.write("**4. Dekripsi Caesar (Final Plaintext):**")
            st.code(d4, language="text")
            
            st.success("Dekripsi Super Enkripsi Berhasil!")
        except Exception as e:
            st.error(f"Kegagalan Dekripsi. Pastikan data tidak korup. Detail: {e}")