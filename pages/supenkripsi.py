import streamlit as st
from crypto_engine import (
    caesar_encrypt_core, caesar_decrypt_core,
    railfence_encrypt_core, railfence_decrypt_core,
    chacha20_encrypt_core, chacha20_decrypt_core,
    aes_encrypt_core, aes_decrypt_core,
    derive_keys
)

st.set_page_config(page_title="Super Enkripsi", layout="wide")
st.title("Menu 5: Super Enkripsi (Kombinasi 4 Algoritma)")

master_pwd = st.text_input("Master Password (1 Kunci untuk Semua)", value="RAHASIA123", type="password")
k_ca, k_rf, k_ch, k_ae = derive_keys(master_pwd)

tab1, tab2 = st.tabs(["Super Enkripsi", "Super Dekripsi"])

with tab1:
    plaintext = st.text_area("Masukkan Plaintext")
    if st.button("Eksekusi Enkripsi", type="primary") and plaintext:
        r1 = caesar_encrypt_core(plaintext, k_ca)
        r2 = railfence_encrypt_core(r1, k_rf)
        r3 = chacha20_encrypt_core(r2, k_ch)
        r4 = aes_encrypt_core(r3, k_ae)
        
        st.write("**1. Caesar:**", r1)
        st.write("**2. Rail Fence:**", r2)
        st.write("**3. ChaCha20:**", r3)
        st.write("**4. Final AES-128:**")
        st.code(r4, language="text")

with tab2:
    ciphertext = st.text_area("Super Ciphertext (Hex)")
    if st.button("Eksekusi Dekripsi", type="primary") and ciphertext:
        try:
            d1 = aes_decrypt_core(ciphertext.strip(), k_ae)
            d2 = chacha20_decrypt_core(d1, k_ch)
            d3 = railfence_decrypt_core(d2, k_rf)
            d4 = caesar_decrypt_core(d3, k_ca)
            
            st.write("**1. Decrypt AES:**", d1)
            st.write("**2. Decrypt ChaCha20:**", d2)
            st.write("**3. Decrypt Rail Fence:**", d3)
            st.write("**4. Final Plaintext:**")
            st.code(d4, language="text")
        except Exception as e:
            st.error(f"Gagal Dekripsi: {e}")