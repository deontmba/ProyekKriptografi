import streamlit as st
# Import modul layout yang sudah kita buat sebelumnya
from ui import layout 

# ==========================================
# 1. KONFIGURASI HALAMAN (WAJIB PALING ATAS)
# ==========================================
st.set_page_config(
    page_title="AES Encryption Lab",
    page_icon="🔐",
    layout="wide",  # Gunakan 'wide' agar tema ungu terlihat lebih lega dan profesional
    initial_sidebar_state="expanded"
)

layout.init_ui()

# Import fungsi-fungsi UI lainnya
from ui.layout import (
    header,
    text_encryption_ui,
    file_encryption_ui,
    cbc_text_ui,
    cbc_file_ui,
    lab_ecb_manual_ui,
    lab_cbc_manual_ui
)

# ====== SESSION STATE UNTUK MODE ======
if "mode" not in st.session_state:
    st.session_state.mode = None
    
    # ===== TOP NAVIGATION BAR =====
if st.session_state.mode is not None:

    col1, col2, col3 = st.columns([1, 1, 1])

    with col1:
        if st.button("AES-ECB 🔳", use_container_width=True):
            st.session_state.mode = "ECB"
            st.rerun()

    with col2:
        if st.button("AES-CBC 🔗", use_container_width=True):
            st.session_state.mode = "CBC"
            st.rerun()

    with col3:
        if st.button("↩ Kembali", use_container_width=True):
            st.session_state.mode = None
            st.rerun()


# ====== MODE SELECTION SCREEN ======
if st.session_state.mode is None:
    header(show_expander=True)
    st.markdown("<br>", unsafe_allow_html=True) # Spacer
    st.markdown("### 🔰 Pilih Mode Enkripsi")
    st.write("Silakan pilih mode enkripsi yang ingin dipelajari:")

    col1, col2 = st.columns(2)

    with col1:
        # Menggunakan container styling dari CSS baru
        with st.container():
            st.markdown("### 🔐 AES-ECB")
            st.caption("Sederhana, pola data masih terlihat → cocok untuk belajar.")
            if st.button("Gunakan Mode ECB 📌", use_container_width=True):
                st.session_state.mode = "ECB"
                st.rerun() # Gunakan st.rerun() (versi baru) atau st.experimental_rerun()

    with col2:
        with st.container():
            st.markdown("### 🧱 AES-CBC")
            st.caption("Mode chaining, jauh lebih aman untuk data nyata.")
            if st.button("Gunakan Mode CBC 🧱", use_container_width=True):
                st.session_state.mode = "CBC"
                st.rerun()

    st.stop() # Berhenti render di sini jika mode belum dipilih
else:
    header(show_expander=False)

# ====== SIDEBAR & TOMBOL KEMBALI ======
# st.sidebar.title("Navigasi")
# st.sidebar.info(f"Modul Aktif: **AES-{st.session_state.mode}**")

# if st.sidebar.button("↩ Kembali ke Menu Utama"):
#     st.session_state.mode = None
#     st.rerun()

# ====== HALAMAN SESUAI MODE ======
if st.session_state.mode == "ECB":
    tabs = st.tabs(["📝 Teks (ECB)", "📁 File (ECB)", "🧬 Lab ECB"])
    with tabs[0]:
        text_encryption_ui()
    with tabs[1]:
        file_encryption_ui()
    with tabs[2]:
        st.info("👨‍🔬 Eksperimen manual AES-ECB (Enkripsi Blok Tunggal)")
        lab_ecb_manual_ui()

elif st.session_state.mode == "CBC":
    tabs = st.tabs(["📝 Teks (CBC)", "📁 File (CBC)", "🧪 Lab CBC"])
    with tabs[0]:
        cbc_text_ui()
    with tabs[1]:
        cbc_file_ui()
    with tabs[2]:
        st.info("👨‍🔬 Eksperimen manual AES-CBC (Cipher Block Chaining)")
        lab_cbc_manual_ui()

# ====== FOOTER ======
st.markdown("<br><hr>", unsafe_allow_html=True)
st.markdown(
    """
    <div style='text-align: center; color: #94a3b8; font-size: 0.8rem;'>
        Made for Educational Crypto Lab 🔐 | AES-ECB & AES-CBC | Informatika ✨
    </div>
    """, 
    unsafe_allow_html=True
)