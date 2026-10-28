import os
import streamlit as st
import pandas as pd
from crypto_engine import chacha20_encrypt_core, chacha20_decrypt_core
import hashlib

st.set_page_config(page_title="ChaCha20 Stream Cipher", layout="wide")

MASK32 = 0xFFFFFFFF

def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32

def quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
    s[a] = (s[a] + s[b]) & MASK32; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
    s[c] = (s[c] + s[d]) & MASK32; s[b] ^= s[c]; s[b] = rotl(s[b], 7)

def chacha20_block_with_trace(key: bytes, nonce: bytes, counter: int):
    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    kw = [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    nw = [int.from_bytes(nonce[i:i + 4], "little") for i in range(0, 8, 4)]
    if len(nw) == 2: nw = [0] + nw
    state = constants + kw + [counter] + nw
    w = state.copy()
    for _ in range(10): 
        quarter_round(w, 0, 4, 8, 12); quarter_round(w, 1, 5, 9, 13)
        quarter_round(w, 2, 6, 10, 14); quarter_round(w, 3, 7, 11, 15)
        quarter_round(w, 0, 5, 10, 15); quarter_round(w, 1, 6, 11, 12)
        quarter_round(w, 2, 7, 8, 13); quarter_round(w, 3, 4, 9, 14)
    out = [(w[i] + state[i]) & MASK32 for i in range(16)]
    keystream = b"".join(x.to_bytes(4, "little") for x in out)
    return keystream, state, w

st.title("ChaCha20")
st.caption("Algoritma Stream Cipher Modern (ARX)")

with st.sidebar:
    st.subheader("Konfigurasi Kunci")
    pwd = st.text_input("Password (di-hash ke 32-byte):", value="RAHASIA")
    key_32 = hashlib.sha256(pwd.encode('utf-8')).digest()
    st.code(key_32.hex(), language="text")

tab_enc, tab_dec, tab_viz = st.tabs(["Enkripsi", "Dekripsi", "Visualisasi Operasi Bit"])

with tab_enc:
    pt = st.text_area("Plaintext", key="pt_ch")
    if st.button("Jalankan Enkripsi", type="primary"):
        if pt:
            ct_hex = chacha20_encrypt_core(pt, key_32)
            st.success("Enkripsi Selesai")
            st.markdown("**Ciphertext Akhir (Hex + Nonce):**")
            st.code(ct_hex, language="text")

with tab_dec:
    ct = st.text_area("Ciphertext (Hex)", key="ct_ch")
    if st.button("Jalankan Dekripsi", type="primary"):
        if ct:
            try:
                hasil = chacha20_decrypt_core(ct.strip(), key_32)
                st.success("Dekripsi Selesai")
                st.code(hasil, language="text")
            except Exception as e:
                st.error("Format data tidak valid atau kunci salah.")

with tab_viz:
    st.markdown("Visualisasi pembuatan Keystream dan operasi XOR per Byte (Maksimal 64 karakter pertama).")
    msg = st.text_area("Pesan Analisis", value="Uji Coba ChaCha20", key="msg_viz_ch")
    if st.button("Bedah Proses Stream"):
        if msg:
            pt_bytes = msg.encode('utf-8')[:64]
            dummy_nonce = os.urandom(8)
            keystream, state0, state_final = chacha20_block_with_trace(key_32, dummy_nonce, 1)
            
            st.subheader("1. State Awal Matriks (32-bit Words)")
            state_hex = [f"{x:08x}" for x in state0]
            st.code("\n".join([" ".join(state_hex[i:i+4]) for i in range(0, 16, 4)]), language="text")
            
            st.subheader("2. Hasil Keystream setelah 20 Ronde ARX (Hex)")
            st.code(keystream.hex(), language="text")
            
            st.subheader("3. Operasi XOR Linear per Byte")
            xor_data = []
            for i in range(len(pt_bytes)):
                p = pt_bytes[i]
                k = keystream[i]
                c = p ^ k
                xor_data.append({
                    "Byte Posisi": i+1,
                    "Karakter": chr(p) if 32 <= p <= 126 else ".",
                    "Plaintext (Dec/Hex)": f"{p} (0x{p:02x})",
                    "Keystream (Dec/Hex)": f"{k} (0x{k:02x})",
                    "Ciphertext (Dec/Hex)": f"{c} (0x{c:02x})"
                })
            st.dataframe(pd.DataFrame(xor_data), use_container_width=True)