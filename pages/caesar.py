from __future__ import annotations
import streamlit as st
import pandas as pd
from dataclasses import dataclass, field

st.set_page_config(page_title="Caesar Cipher", layout="wide")

# ==========================================
# LOGIKA INTI CAESAR (Dari Temanmu)
# ==========================================
@dataclass(frozen=True)
class Step:
    no: int
    char: str
    is_letter: bool
    start: int | None
    shift: int | None
    end: int | None
    out: str
    calc: str

@dataclass(frozen=True)
class Result:
    mode: str  # "enc" | "dec"
    shift: int
    input: str
    output: str
    steps: list[Step] = field(default_factory=list)

def validate_shift(raw) -> int:
    s = str(raw if raw is not None else "").strip()
    if not s:
        raise ValueError("Key Caesar tidak boleh kosong.")
    try:
        k = int(s)
    except ValueError:
        raise ValueError("Key Caesar harus berupa bilangan bulat (contoh: 3).") from None
    if not 1 <= k <= 25:
        raise ValueError("Key Caesar harus berada pada rentang 1–25.")
    return k

def _base(ch: str) -> int | None:
    if "A" <= ch <= "Z": return 65
    if "a" <= ch <= "z": return 97
    return None

def process(text: str, shift, decrypt: bool = False) -> Result:
    k = validate_shift(shift)
    steps: list[Step] = []
    out: list[str] = []
    for i, ch in enumerate(text, 1):
        base = _base(ch)
        if base is None:
            steps.append(Step(i, ch, False, None, None, None, ch, "Bukan huruf → tidak diubah"))
            out.append(ch)
            continue
        p = ord(ch) - base
        if decrypt:
            v = (p - k) % 26
            calc = f"({p} − {k}) mod 26 = {v}"
        else:
            v = (p + k) % 26
            calc = f"({p} + {k}) mod 26 = {v}"
        r = chr(v + base)
        steps.append(Step(i, ch, True, p, k, v, r, calc))
        out.append(r)
    return Result("dec" if decrypt else "enc", k, text, "".join(out), steps)

# ==========================================
# ANTARMUKA STREAMLIT
# ==========================================
st.title("🏛️ Caesar Cipher")
st.caption("Algoritma Substitusi Klasik")

with st.sidebar:
    st.subheader("Konfigurasi Kunci")
    shift_key = st.number_input("Masukkan Kunci (Shift 1-25):", min_value=1, max_value=25, value=3)

tab_enc, tab_dec = st.tabs(["Enkripsi", "Dekripsi"])

with tab_enc:
    pt = st.text_area("Plaintext", placeholder="Masukkan teks...", key="pt_ca")
    if st.button("Enkripsi", type="primary", key="btn_enc_ca"):
        if pt:
            try:
                hasil = process(pt, shift_key, decrypt=False)
                st.success("Enkripsi Berhasil!")
                st.markdown("**Ciphertext:**")
                st.code(hasil.output, language="text")
                
                st.subheader("Trace Proses Langkah demi Langkah")
                # Mengubah dataclass steps menjadi tabel UI
                df = pd.DataFrame([
                    {"No": s.no, "Karakter Asli": s.char, "Status": "Huruf" if s.is_letter else "Abaikan", 
                     "Hitungan": s.calc, "Karakter Hasil": s.out} 
                    for s in hasil.steps
                ])
                st.dataframe(df, use_container_width=True)
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Plaintext kosong.")

with tab_dec:
    ct = st.text_area("Ciphertext", placeholder="Masukkan ciphertext...", key="ct_ca")
    if st.button("Dekripsi", type="primary", key="btn_dec_ca"):
        if ct:
            try:
                hasil = process(ct, shift_key, decrypt=True)
                st.success("Dekripsi Berhasil!")
                st.markdown("**Plaintext:**")
                st.code(hasil.output, language="text")
                
                st.subheader("Trace Proses Langkah demi Langkah")
                df = pd.DataFrame([
                    {"No": s.no, "Karakter Asli": s.char, "Status": "Huruf" if s.is_letter else "Abaikan", 
                     "Hitungan": s.calc, "Karakter Hasil": s.out} 
                    for s in hasil.steps
                ])
                st.dataframe(df, use_container_width=True)
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.warning("Ciphertext kosong.")