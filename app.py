import streamlit as st

# ==========================================
# 1. KONFIGURASI GLOBAL (Wajib Paling Atas)
# ==========================================
# Konfigurasi ini akan diwariskan ke semua halaman di dalam folder pages/
st.set_page_config(
    page_title="Tugas Kriptografi",
    layout="centered",
    initial_sidebar_state="expanded"
)

# ==========================================
# 2. HEADER & JUDUL
# ==========================================
st.title("Aplikasi Kriptografi Terintegrasi")
st.subheader("Implementasi Algoritma Klasik, Modern, dan Super Enkripsi")
st.divider()

# ==========================================
# 3. DESKRIPSI & PANDUAN PENGGUNAAN
# ==========================================
st.markdown("""
Selamat datang di aplikasi demonstrasi kriptografi. Aplikasi ini dibangun menggunakan arsitektur **Modular Multipage** untuk memastikan setiap algoritma berjalan secara terisolasi tanpa kebocoran memori (variable bleeding) antar menu.

**Silakan gunakan navigasi Sidebar di sebelah kiri untuk mengakses modul:**

*   **Menu 1: Caesar Cipher** (Algoritma Substitusi Klasik)
*   **Menu 2: Rail Fence Cipher** (Algoritma Transposisi Klasik)
*   **Menu 3: ChaCha20** (Stream Cipher Modern - Arsitektur ARX)
*   **Menu 4: AES-128** (Block Cipher Modern - Arsitektur SPN)
*   **Menu 5: Super Enkripsi** (Enkripsi Berantai dengan Key Derivation)

*Catatan: Setiap menu algoritma dilengkapi dengan fitur **Visualisasi Trace** untuk membedah operasi perhitungan matematis dan transformasi matriks/byte secara detail sesuai standar evaluasi.*
""")

st.divider()

# ==========================================
# 4. INFORMASI KELOMPOK
# ==========================================
st.markdown("### Tim Pengembang")
st.markdown("""
*   **Aditya Putra Septemberiano (123240216)** — Modul AES-128 & Super Enkripsi
*   **[Nama Teman 1] ([NIM 1])** — Modul ChaCha20
*   **[Nama Teman 2] ([NIM 2])** — Modul Caesar Cipher & Rail Fence
*   **[Nama Teman 3] ([NIM 3])** — [Tugas Lainnya jika kelompok ber-4]
""")

st.info("Petunjuk Presentasi: Mulailah demonstrasi dari algoritma tunggal (Menu 1-4) untuk memvalidasi pemahaman matematis, lalu buka Menu 5 untuk menguji aliran data (Data Flow) gabungan.")