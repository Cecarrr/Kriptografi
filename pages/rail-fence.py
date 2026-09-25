import streamlit as st

st.set_page_config(page_title="Rail Fence Cipher", layout="wide")

# ==========================================
# LOGIKA INTI RAIL FENCE (Dari Temanmu)
# ==========================================
def fence(lst, numrails):
    fence = [[None] * len(lst) for n in range(numrails)]
    rails = list(range(numrails - 1)) + list(range(numrails - 1, 0, -1))
    for n, x in enumerate(lst):
        fence[rails[n % len(rails)]][n] = x
    return [c for rail in fence for c in rail if c is not None]

def encode(text, n):
    if n < 2 or not text: return text
    return "".join(fence(text, n))

def decode(text, n):
    if n < 2 or not text: return text
    rng = range(len(text))
    pos = fence(rng, n)
    return "".join(text[pos.index(n)] for n in rng)

# ==========================================
# ANTARMUKA STREAMLIT
# ==========================================
st.title("🛤️ Rail Fence Cipher")
st.caption("Algoritma Transposisi Klasik (Zig-Zag)")

with st.sidebar:
    st.subheader("Konfigurasi Kunci")
    rails = st.number_input("Jumlah Baris (Rails):", min_value=2, max_value=20, value=3)
    st.caption("Minimal 2 baris agar transposisi bekerja.")

tab_enc, tab_dec = st.tabs(["Enkripsi", "Dekripsi"])

with tab_enc:
    pt = st.text_area("Plaintext", placeholder="Contoh: ATTACK.AT.DAWN", key="pt_rf")
    if st.button("Enkripsi", type="primary", key="btn_enc_rf"):
        if pt:
            hasil = encode(pt, rails)
            st.success("Enkripsi Berhasil!")
            st.markdown("**Ciphertext:**")
            st.code(hasil, language="text")
        else:
            st.warning("Plaintext tidak boleh kosong.")

with tab_dec:
    ct = st.text_area("Ciphertext", placeholder="Masukkan ciphertext...", key="ct_rf")
    if st.button("Dekripsi", type="primary", key="btn_dec_rf"):
        if ct:
            hasil = decode(ct, rails)
            st.success("Dekripsi Berhasil!")
            st.markdown("**Plaintext Asli:**")
            st.code(hasil, language="text")
        else:
            st.warning("Ciphertext tidak boleh kosong.")