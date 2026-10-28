import streamlit as st
from crypto_engine import railfence_encrypt_core, railfence_decrypt_core

st.set_page_config(page_title="Rail Fence Cipher", layout="wide")

def trace_railfence_grid(text, key, mode="enc"):
    if key < 2: return text
    rail = [['.' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0
    
    if mode == "enc":
        for i in range(len(text)):
            if (row == 0) or (row == key - 1): dir_down = not dir_down
            rail[row][col] = text[i]
            col += 1
            row += 1 if dir_down else -1
    else:
        for i in range(len(text)):
            if row == 0: dir_down = True
            if row == key - 1: dir_down = False
            rail[row][col] = '*'
            col += 1
            row += 1 if dir_down else -1
        index = 0
        for i in range(key):
            for j in range(len(text)):
                if (rail[i][j] == '*') and (index < len(text)):
                    rail[i][j] = text[index]
                    index += 1
                    
    grid_str = ""
    for r in rail:
        grid_str += "  ".join(r) + "\n"
    return grid_str

st.title("Rail Fence Cipher")
st.caption("Algoritma Transposisi Klasik")

with st.sidebar:
    st.subheader("Konfigurasi")
    rails = st.number_input("Jumlah Baris (Rails):", min_value=2, max_value=20, value=3)

tab_enc, tab_dec = st.tabs(["Enkripsi", "Dekripsi"])

with tab_enc:
    pt = st.text_area("Plaintext", key="pt_rf")
    if st.button("Jalankan Enkripsi", type="primary"):
        if pt:
            hasil = railfence_encrypt_core(pt, rails)
            st.success("Enkripsi Selesai")
            st.code(hasil, language="text")
            st.subheader("Visualisasi Matriks Transposisi")
            st.code(trace_railfence_grid(pt, rails, "enc"), language="text")

with tab_dec:
    ct = st.text_area("Ciphertext", key="ct_rf")
    if st.button("Jalankan Dekripsi", type="primary"):
        if ct:
            hasil = railfence_decrypt_core(ct, rails)
            st.success("Dekripsi Selesai")
            st.code(hasil, language="text")
            st.subheader("Visualisasi Rekonstruksi Matriks")
            st.code(trace_railfence_grid(ct, rails, "dec"), language="text")