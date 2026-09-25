import streamlit as st

# 1. Konfigurasi Global (Wajib diletakkan paling atas)
# Konfigurasi ini akan berlaku untuk SEMUA halaman di dalam folder pages/
st.set_page_config(
    page_title="Tugas Kriptografi",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded"
)

# 2. Header & Judul Landing Page
st.title("🛡️ Aplikasi Kriptografi Terintegrasi")
st.subheader("Implementasi Algoritma Klasik, Modern, dan Super Enkripsi")
st.divider()

# 3. Deskripsi & Panduan Penggunaan
st.markdown("""
Selamat datang di aplikasi demonstrasi kriptografi. Aplikasi ini dibangun menggunakan arsitektur **Modular Multipage** untuk memastikan setiap algoritma berjalan secara terisolasi tanpa *variable bleeding* (kebocoran memori antar menu).

**Silakan gunakan Sidebar di sebelah kiri untuk menavigasi modul:**

*   **Menu 1: Caesar Cipher** (Algoritma Substitusi Klasik)
*   **Menu 2: Rail Fence Cipher** (Algoritma Transposisi Klasik)
*   **Menu 3: ChaCha20-Poly1305** (Stream Cipher Modern - Arsitektur ARX)
*   **Menu 4: AES-128** (Block Cipher Modern - Arsitektur SPN)
*   **Menu 5: Super Enkripsi** (Enkripsi Berantai dengan *Key Derivation*)

*Catatan: Menu 3 dan 4 dilengkapi dengan fitur **Visualisasi Trace** untuk membedah operasi bit/hex di dalam algoritma (RFC 8439 & Operasi Matriks).*
""")

st.divider()

# 4. Informasi Kelompok
st.markdown("### 👨‍💻 Tim Pengembang")
st.markdown("""
*   **Aditya Putra Septemberiano (123240216)** — 
*   **CAESAR SABILLAH KIVASHA PUTRA PURNOMO (123240056)**
*   **MICHAEL BINTANG FEBRYAN SUKMA JATI (123240145)** 
*   **SHAFIQ SHIDQI AZIZI (123240085)** 
""")
