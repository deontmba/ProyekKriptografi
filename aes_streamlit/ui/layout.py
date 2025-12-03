import streamlit as st
import streamlit.components.v1 as components
import base64
import os

# --- IMPORT CORE LOGIC (Jangan dihapus) ---
from core.aes_manual_demo import (
    aes128_encrypt_block_with_steps,
    aes128_decrypt_block_with_steps,
)
from core.key_utils import pad_pkcs7
from core.file_crypto import decrypt_file, encrypt_file
from core.text_crypto import (
    encrypt_text,
    decrypt_text,
    visualize_text_encryption,
    visualize_text_decryption,
)
from core.crypto_cbc import (
    encrypt_text_cbc,
    decrypt_text_cbc,
    encrypt_file_cbc,
    decrypt_file_cbc,
    visualize_cbc_text,
)
from core.aes_cbc_manual_demo import (
    cbc_manual_encrypt_one_block_from_text,
    cbc_manual_decrypt_one_block_from_hex
)

# ==========================================
# 🎨 1. GLOBAL STYLING (CSS LANGSUNG DISINI)
# ==========================================
def init_ui():
    st.markdown("""
    <style>
        /* Import Font Keren */
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;500;700&family=JetBrains+Mono:wght@400;700&display=swap');

        /* --- BACKGROUND UTAMA (WAJIB BERUBAH) --- */
        [data-testid="stAppViewContainer"] {
            background-color: #05020a !important;
            background-image: linear-gradient(180deg, #1a0b2e 0%, #11051f 50%, #000000 100%) !important;
            background-attachment: fixed !important;
            background-size: cover !important;
        }
        
        
        /* Header Transparan */
        [data-testid="stHeader"] {
            background: rgba(0,0,0,0) !important;
        }

        /* Sidebar Gelap */
        [data-testid="stSidebar"] {
            background-color: #0b0214 !important;
            border-right: 1px solid #2e1065;
        }
        
            /* ====== TOP NAV BAR ====== */
    .top-nav {
        width: 100%;
        padding: 10px 20px;
        display: flex;
        justify-content: center;
        gap: 20px;
        background: rgba(15, 5, 24, 0.6);
        position: sticky;
        top: 0;
        z-index: 999;
        border-bottom: 1px solid #4c1d95;
        backdrop-filter: blur(12px);
    }

    .top-nav a {
        text-decoration: none;
        color: #c084fc;
        font-weight: 600;
        padding: 6px 14px;
        border-radius: 6px;
        transition: 0.25s;
    }

    .top-nav a:hover {
        color: white;
        background: linear-gradient(90deg,#7c3aed,#db2777);
        box-shadow: 0 0 10px rgba(124,58,237,0.7);
    }

    /* Tombol Active */
    .active-nav {
        color: white !important;
        background: linear-gradient(90deg,#7c3aed,#db2777);
        border-radius: 6px;
    }
    
    /* === Top Navigation Button Styling (Compact Version) === */
.stButton > button {
    background: linear-gradient(90deg, #7c3aed 0%, #db2777 100%) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 6px !important;
    
    /* Ukuran tombol lebih kecil */
    padding: 0.35rem 0.8rem !important;
    font-size: 0.78rem !important;
    font-weight: 600 !important;
    
    /* Shadow lebih halus */
    box-shadow: 0 2px 10px rgba(124, 58, 237, 0.3) !important;
    transition: all 0.2s ease !important;
}

.stButton > button:hover {
    transform: translateY(-1.5px) !important;
    box-shadow: 0 5px 14px rgba(219, 39, 119, 0.45) !important;
}

    
    
        /* --- TYPOGRAPHY --- */
        html, body, [class*="css"] {
            font-family: 'Outfit', sans-serif;
            color: #e9d5ff !important; /* Warna Teks Lavender */
        }
        
        h1, h2, h3 {
            color: #d8b4fe !important; /* Judul Ungu Terang */
            font-weight: 700;
        }
        
        /* Font Coding */
        .stCode, code, .stTextInput input, .stTextArea textarea {
            font-family: 'JetBrains Mono', monospace !important;
        }

        /* --- WIDGET INPUT (Transparan & Border Ungu) --- */
        .stTextInput > div > div, 
        .stTextArea > div > div, 
        .stSelectbox > div > div {
            background-color: rgba(255, 255, 255, 0.05) !important;
            color: #ffffff !important;
            border: 1px solid #581c87 !important;
            border-radius: 8px !important;
        }
        
        /* Fokus pada Input */
        .stTextInput > div > div:focus-within {
            border-color: #d8b4fe !important;
            box-shadow: 0 0 10px rgba(216, 180, 254, 0.2) !important;
        }

        /* --- TOMBOL (Neon Gradient) --- */
        .stButton > button {
            background: linear-gradient(90deg, #7c3aed 0%, #db2777 100%) !important;
            color: white !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 0.6rem 1.2rem !important;
            font-weight: 600 !important;
            box-shadow: 0 4px 15px rgba(124, 58, 237, 0.4) !important;
            transition: all 0.3s ease !important;
        }
        
        .stButton > button:hover {
            transform: translateY(-2px) !important;
            box-shadow: 0 6px 20px rgba(219, 39, 119, 0.6) !important;
        }

        /* --- TABS --- */
        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
            border-bottom: 1px solid #4c1d95;
        }
        
        .stTabs [data-baseweb="tab"] {
            background-color: transparent;
            border: none;
            color: #a78bfa;
        }
        
        .stTabs [aria-selected="true"] {
            background-color: rgba(124, 58, 237, 0.2) !important;
            border-radius: 6px;
            color: #e879f9 !important;
            border: 1px solid #7c3aed;
        }

        /* --- EXPANDER & INFO BOXES --- */
        .streamlit-expanderHeader {
            background-color: rgba(255, 255, 255, 0.05) !important;
            color: #e9d5ff !important;
            border-radius: 8px;
        }
        
        /* Info/Success/Error Messages Background */
        .stAlert {
            background-color: rgba(15, 5, 24, 0.8) !important;
            border: 1px solid #4c1d95 !important;
            color: #e9d5ff !important;
        }
}
    </style>
    """, unsafe_allow_html=True)

# ==========================================
# 🏠 2. HEADER & HOME (HTML Custom)
# ==========================================
def header(show_expander=True):
    # Judul Utama
    st.html("""
        <div style="
            text-align: center; 
            padding: 3rem 1rem; 
            margin-bottom: 2rem;
            background: radial-gradient(circle, rgba(76, 29, 149, 0.2) 0%, rgba(0,0,0,0) 70%);
            border-bottom: 1px solid rgba(139, 92, 246, 0.1);">
            
            <h1 style="
                margin: 0; 
                font-size: 3.5rem; 
                background: linear-gradient(to right, #c084fc, #e879f9); 
                -webkit-background-clip: text; 
                -webkit-text-fill-color: transparent;
                text-shadow: 0 0 40px rgba(192, 132, 252, 0.4);">
                🔐 AES Crypto Lab
            </h1>
            
            <p style="
                color: #a78bfa; 
                font-size: 1.1rem; 
                margin-top: 15px; 
                letter-spacing: 1px;">
                MODERN ENCRYPTION PLAYGROUND <span style="color: #e879f9;">|</span> ECB & CBC
            </p>
        </div>
    """)
    if show_expander:
        with st.expander("ℹ️ Konsep: Apa perbedaan ECB dan CBC?", expanded=False):
            st.html("""
            <div style="
                background-color: rgba(15, 5, 24, 0.8); 
                padding: 20px; 
                border-radius: 12px; 
                border: 1px solid #4c1d95;">
                
                <h3 style="margin-top:0; color: #d8b4fe; border-bottom: 1px solid #2e1065; padding-bottom: 10px;">
                    🧠 Tentang AES
                </h3>
                <p style="color: #cbd5e1;">AES adalah <i>block cipher</i> modern yang mengenkripsi data dalam blok <b>16 byte</b>.</p>
                
                <div style="display: flex; gap: 20px; flex-wrap: wrap; margin-top: 20px;">
                    <div style="flex: 1; min-width: 200px; background: rgba(255,255,255,0.03); padding: 15px; border-radius: 10px; border-left: 3px solid #c084fc;">
                        <h4 style="color: #c084fc; margin-top:0;">🔳 Mode ECB</h4>
                        <ul style="color: #cbd5e1; padding-left: 20px;">
                            <li>Enkripsi <b>independen</b>.</li>
                            <li style="color: #f472b6;">❗ Pola terlihat.</li>
                            <li>✔ Mudah dipelajari.</li>
                        </ul>
                    </div>
                    
                    <div style="flex: 1; min-width: 200px; background: rgba(255,255,255,0.03); padding: 15px; border-radius: 10px; border-left: 3px solid #e879f9;">
                        <h4 style="color: #e879f9; margin-top:0;">🔗 Mode CBC</h4>
                        <ul style="color: #cbd5e1; padding-left: 20px;">
                            <li><b>XOR</b> dengan blok sebelumnya.</li>
                            <li style="color: #4ade80;">✔ Pola teracak total.</li>
                            <li>📌 Standar aman.</li>
                        </ul>
                    </div>
                </div>
            </div>
        """)

## ======== UI ENKRIPSI TEKS ========= #
def text_encryption_ui():
    st.subheader("📝 Enkripsi / Dekripsi Teks")

    tab1, tab2, tab3, tab4 = st.tabs([
        "🔒 Enkripsi Teks",
        "🔓 Dekripsi Teks",
        "🧬 Visualisasi Enkripsi AES-ECB",
        "🧪 Visualisasi Dekripsi AES-ECB"
    ])


    # ----- TAB ENKRIPSI ----- #
    with tab1:
        plaintext = st.text_area("Masukan plaintext:", height=150, key="enc_text_plain")
        user_key = st.text_input("Masukan kunci:", type="password", key="enc_text_key")

        if st.button("🔐 Enkripsi Teks", key="btn_enc_text"):
            try:
                cipher = encrypt_text(plaintext, user_key)
                st.success("Teks berhasil dienkripsi! Berikut ciphertext dalam Base64:")
                st.code(cipher, language="text")
            except Exception as e:
                st.error(f"Error: {e}")

    # ----- TAB DEKRIPSI ----- #
    with tab2:
        cipher_b64 = st.text_area("Masukan ciphertext (Base64):", height=150, key="dec_text_cipher")
        user_key_dec = st.text_input("Masukan kunci (untuk dekripsi):", type="password", key="dec_text_key")

        if st.button("🔓 Dekripsi Teks", key="btn_dec_text"):
            try:
                plain = decrypt_text(cipher_b64, user_key_dec)
                st.success("Teks berhasil didekripsi! Berikut plaintext:")
                st.code(plain, language="text")
            except Exception as e:
                st.error(f"Error: {e}")

    # ----- TAB VISUALISASI ENKRIPSI ----- #
    with tab3:
        st.markdown("### 🔍 Visualisasi Enkripsi AES-ECB untuk Teks")
        st.write("Tab ini menjelaskan **bagaimana plaintext dan kunci diolah menjadi ciphertext** langkah demi langkah.")

        vis_plain = st.text_area("Plaintext untuk divisualisasikan:", height=120, key="vis_text_plain_enc")
        vis_key = st.text_input("Kunci:", type="password", key="vis_text_key_enc")

        if st.button("▶ Jalankan Visualisasi Enkripsi", key="btn_vis_text_enc"):
            try:
                data = visualize_text_encryption(vis_plain, vis_key)

                st.markdown("#### 1️⃣ Plaintext → Bytes")
                st.write("Plaintext diubah menjadi deretan byte (UTF-8):")
                st.code(data["plaintext_bytes_hex"], language="text")

                st.markdown("#### 2️⃣ Kunci → Key AES-256")
                st.write("Kunci yang kamu masukkan di-hash dan dipotong menjadi 32 byte (AES-256):")
                st.code(data["key_bytes_hex"], language="text")

                st.markdown("#### 3️⃣ Pemecahan Menjadi Blok 16 Byte + Padding PKCS#7")
                st.info("AES selalu bekerja dalam blok 16 byte. Jika panjang data tidak pas, PKCS#7 menambahkan padding.")
                for block in data["blocks"]:
                    st.markdown(f"**Blok {block['index']}** (setelah padding, selalu 16 byte):")
                    st.markdown("• Plaintext (hex):")
                    st.code(block["plaintext_block_hex"], language="text")
                    st.markdown("• Ciphertext (hex):")
                    st.code(block["ciphertext_block_hex"], language="text")

                st.markdown("#### 4️⃣ Ciphertext Akhir (Base64)")
                st.write("Seluruh blok ciphertext digabung lalu dikonversi ke Base64:")
                st.code(data["ciphertext_b64"], language="text")

            except Exception as e:
                st.error(f"Error: {e}")

    # ----- TAB VISUALISASI DEKRIPSI ----- #
    with tab4:
        st.markdown("### 🧪 Visualisasi Dekripsi AES-ECB untuk Teks")
        st.write(
            "Di sini kamu bisa melihat **bagaimana ciphertext (Base64) dikembalikan menjadi plaintext** "
            "melalui langkah: Base64 → bytes → blok → decrypt → buang padding."
        )

        vis_cipher_b64 = st.text_area("Ciphertext (Base64):", height=120, key="vis_text_cipher_dec")
        vis_key_dec = st.text_input("Kunci:", type="password", key="vis_text_key_dec")

        if st.button("▶ Jalankan Visualisasi Dekripsi", key="btn_vis_text_dec"):
            try:
                data = visualize_text_decryption(vis_cipher_b64, vis_key_dec)

                st.markdown("#### 1️⃣ Ciphertext (Base64) → Bytes (Hex)")
                st.write(
                    "Langkah pertama, ciphertext dalam format Base64 di-decode menjadi deretan byte biner. "
                    "Inilah representasi heksadesimalnya:"
                )
                st.code(data["ciphertext_bytes_hex"], language="text")

                st.markdown("#### 2️⃣ Kunci → Key AES-256")
                st.write(
                    "Kunci yang kamu input diproses dengan cara yang sama seperti saat enkripsi: "
                    "di-hash lalu dipotong menjadi 32 byte."
                )
                st.code(data["key_bytes_hex"], language="text")

                st.markdown("#### 3️⃣ Pemecahan Ciphertext Menjadi Blok 16 Byte")
                st.write(
                    "Ciphertext dibagi menjadi blok 16 byte. Setiap blok akan didekripsi secara independen "
                    "karena **mode ECB tidak memiliki chaining antar blok**."
                )
                for block in data["blocks"]:
                    st.markdown(f"**Blok {block['index']}** (16 byte):")
                    st.markdown("• Ciphertext (hex):")
                    st.code(block["ciphertext_block_hex"], language="text")
                    st.markdown("• Plaintext hasil decrypt blok ini (masih termasuk padding, hex):")
                    st.code(block["plaintext_block_hex"], language="text")

                st.markdown("#### 4️⃣ Gabungan Semua Blok → Plaintext + Padding")
                st.write(
                    "Semua blok plaintext (hasil decrypt) digabung. Di bagian paling akhir biasanya terdapat "
                    "byte-byte padding PKCS#7:"
                )
                st.code(data["plaintext_bytes_hex"], language="text")

                st.markdown("#### 5️⃣ Analisis Padding PKCS#7")
                if data["padding_valid"]:
                    st.success(
                        f"Padding valid terdeteksi. Nilai padding: {data['padding_len']} (decimal) "
                        f"= {data['padding_len']:02X} (hex), berulang sebanyak {data['padding_len']} byte."
                    )
                    st.write("Byte padding (hex):")
                    st.code(data["padding_hex"], language="text")
                else:
                    st.error(
                        "Padding tidak valid. Ini biasanya berarti kunci salah atau ciphertext rusak. "
                        "Plaintext di bawah mungkin tidak bermakna."
                    )

                st.markdown("#### 6️⃣ Plaintext Akhir (Setelah Buang Padding)")
                if data["padding_valid"] and data["plaintext_str"]:
                    st.write("Setelah padding dibuang, plaintext yang diperoleh adalah:")
                    st.code(data["plaintext_str"], language="text")
                else:
                    st.warning(
                        "Plaintext tidak dapat didekode sebagai teks UTF-8 dengan padding yang valid. "
                        "Kemungkinan kunci salah atau ciphertext bukan teks."
                    )

            except Exception as e:
                st.error(f"Error: {e}")
    
def lab_ecb_manual_ui():
    st.markdown("## 🧾 Laboratorium AES Manual (1 Blok)")
    st.write(
        "Mode ini menampilkan **perhitungan AES-128 manual untuk satu blok 16 byte**, "
        "baik enkripsi maupun dekripsi. Cocok untuk memahami langkah internal AES."
    )

    sub_enc, sub_dec = st.tabs(["🔒 Enkripsi 1 Blok", "🔓 Dekripsi 1 Blok"])

    # ======================= SUBTAB ENKRIPSI =======================
    with sub_enc:
        output_mode_enc = st.radio(
            "Format output cipher:",
            ["HEX", "Base64"],
            key="lab_out_enc"
        )
        lab_plain = st.text_area(
            "Masukan plaintext (akan dipadding & diambil blok pertamanya):",
            key="lab_plain_text",
            height=120,
        )
        lab_key = st.text_input(
            "Masukan kunci (untuk AES-128):", type="password", key="lab_key_text"
        )

        if st.button("🔍 Jalankan Analisis Manual Enkripsi", key="btn_lab_manual_enc"):
            try:
                from core.key_utils import pad_pkcs7
                from core.aes_manual_demo import aes128_encrypt_block_with_steps

                block = pad_pkcs7(lab_plain.encode("utf-8"), block_size=16)[:16]
                result = aes128_encrypt_block_with_steps(block, lab_key)

                st.markdown("### 📌 Blok Plaintext (16 Byte) Setelah Padding")
                st.code(result["plaintext_block_hex"], language="text")

                st.markdown("### 🔐 Kunci AES-128 (Hasil Normalisasi)")
                st.code(result["key_hex"], language="text")

                st.markdown("---")
                st.markdown("## 🔄 Proses Round-by-Round (Enkripsi)")

                for rd in result["rounds"]:
                    st.markdown(f"### 🔷 Round {rd['round']}")
                    st.info(rd["description"])

                    st.markdown("**🔑 Round Key:**")
                    st.code(rd["round_key_hex"], language="text")

                    if "after_sub_bytes_hex" in rd:
                        st.markdown("**🧬 Setelah SubBytes:**")
                        st.code(rd["after_sub_bytes_hex"], language="text")

                    if "after_shift_rows_hex" in rd:
                        st.markdown("**➡ Setelah ShiftRows:**")
                        st.code(rd["after_shift_rows_hex"], language="text")

                    if "after_mix_columns_hex" in rd:
                        st.markdown("**🧮 Setelah MixColumns:**")
                        st.code(rd["after_mix_columns_hex"], language="text")

                    st.markdown("**🔐 Setelah AddRoundKey:**")
                    st.code(rd["after_add_round_key_hex"], language="text")
                    st.markdown("---")

                final_cipher = result["cipher_block_hex"]
                if output_mode_enc == "Base64":
                    from core.aes_manual_demo import _hex_bytes_to_base64
                    final_cipher = _hex_bytes_to_base64(final_cipher)

                st.success("🎉 Hasil Cipher Block:")
                st.code(final_cipher, language="text")

            except Exception as e:
                st.error(f"Error: {e}")

    # ======================= SUBTAB DEKRIPSI =======================
    with sub_dec:
        output_mode_dec = st.radio(
            "Format output plaintext:",
            ["HEX", "Base64"],
            key="lab_out_dec"
        )
        st.write(
            "Masukkan **cipher block hex (16 byte)** dan gunakan kunci yang sama "
            "untuk melihat langkah dekripsinya."
        )

        cipher_hex_str = st.text_input(
            "Cipher block (hex, 16 byte dipisah spasi):",
            key="lab_cipher_hex",
            placeholder="contoh: 13 B6 D2 08 A9 CD F6 5B 06 93 A9 41 E9 35 DC 95",
        )
        lab_key_dec = st.text_input(
            "Masukkan kunci (harus sama):",
            type="password",
            key="lab_key_dec_text",
        )

        if st.button("🔍 Jalankan Analisis Manual Dekripsi", key="btn_lab_manual_dec"):
            try:
                from core.aes_manual_demo import aes128_decrypt_block_with_steps

                parts = [p for p in cipher_hex_str.replace(",", " ").split() if p]
                if len(parts) != 16:
                    raise ValueError("Cipher block harus terdiri dari tepat 16 byte hex.")

                block = bytes(int(x, 16) for x in parts)
                result = aes128_decrypt_block_with_steps(block, lab_key_dec)

                st.success("🎉 Plaintext block setelah dekripsi (termasuk padding):")
                st.code(result["plaintext_block_hex"], language="text")

                final_plain = result["plaintext_block_hex"]
                if output_mode_dec == "Base64":
                    from core.aes_manual_demo import _hex_bytes_to_base64
                    final_plain = _hex_bytes_to_base64(final_plain)

                st.markdown("### 📎 Format pilihan:")
                st.code(final_plain, language="text")

                st.markdown("### 📝 Plaintext terbaca (tanpa padding):")
                st.success(result.get("plaintext_readable", ""))

            except Exception as e:
                st.error(f"Error: {e}")



# ======== UI ENKRIPSI FILE ========= #
def file_encryption_ui():
    st.subheader("📁 Enkripsi / Dekripsi File")

    tab1, tab2 = st.tabs(["🔐 Enkripsi File", "🔓 Dekripsi File"])

    # ----- TAB ENKRIPSI FILE ----- #
    with tab1:
        upload_file = st.file_uploader("Pilih file apa saja untuk dienkripsi:", type=None)
        user_key_file = st.text_input("Masukan kunci:", type="password", key="enc_file_key")

        if st.button("🔐 Enkripsi File"):
            if upload_file and user_key_file:
                file_path = f"/tmp/{upload_file.name}"
                with open(file_path, "wb") as f:
                    f.write(upload_file.getbuffer())

                try:
                    output_path = encrypt_file(file_path, user_key_file)
                    st.success("File berhasil dienkripsi!")
                    
                    with open(output_path, "rb") as f:
                        st.download_button("💾 Download File Enkripsi", f, file_name=os.path.basename(output_path))
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.warning("Masukkan file dan kunci terlebih dahulu.")

    # ----- TAB DEKRIPSI FILE ----- #
    with tab2:
        upload_file_dec = st.file_uploader("Pilih file terenkripsi (.enc):", type=["enc"])
        user_key_file_dec = st.text_input("Masukan kunci (untuk dekripsi):", type="password", key="dec_file_key")

        if st.button("🔓 Dekripsi File"):
            if upload_file_dec and user_key_file_dec:
                file_path = f"/tmp/{upload_file_dec.name}"
                with open(file_path, "wb") as f:
                    f.write(upload_file_dec.getbuffer())

                try:
                    output_path = decrypt_file(file_path, user_key_file_dec)
                    st.success("File berhasil didekripsi!")
                    
                    with open(output_path, "rb") as f:
                        st.download_button("💾 Download File Dekripsi", f, file_name=os.path.basename(output_path))
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.warning("Masukkan file dan kunci terlebih dahulu.")

def cbc_text_ui():
    st.subheader("🧱 AES-CBC — Enkripsi / Dekripsi Teks")

    tab1, tab2, tab3, tab4 = st.tabs([
        "🔒 Enkripsi Teks",
        "🔓 Dekripsi Teks",
        "🧬 Visualisasi Enkripsi AES-CBC",
        "🧪 Visualisasi Dekripsi AES-CBC"
    ])

    # ============ TAB 1 — ENKRIPSI ============
    with tab1:
        key = st.text_input("Masukkan kunci (string bebas):", key="cbc_enc_key")
        plaintext = st.text_area("Masukkan plaintext:", key="cbc_enc_plain", height=120)

        if st.button("🔐 Enkripsi CBC", key="cbc_btn_enc"):
            try:
                result = encrypt_text_cbc(plaintext, key)
                st.success("Enkripsi berhasil!")
                st.code(result, language="text")
            except Exception as e:
                st.error(e)

    # ============ TAB 2 — DEKRIPSI ============
    with tab2:
        key = st.text_input("Masukkan kunci:", key="cbc_dec_key")
        cipher_b64 = st.text_area("Cipher (Base64):", key="cbc_dec_cipher", height=120)

        if st.button("🔓 Dekripsi CBC", key="cbc_btn_dec"):
            try:
                result = decrypt_text_cbc(cipher_b64, key)
                st.success("Dekripsi berhasil!")
                st.code(result, language="text")
            except Exception as e:
                st.error(e)

    # ============ TAB 3 — VISUALISASI ENKRIPSI ============
    with tab3:
        key = st.text_input("Masukkan kunci:", key="cbc_vis_key_enc")
        plaintext = st.text_area("Masukkan plaintext:", key="cbc_vis_plain_enc", height=120)
        iv_hex = st.text_input("IV (opsional, hex 32 karakter):", key="cbc_vis_iv_enc")

        if st.button("🔬 Visualisasi CBC (Enkripsi)", key="btn_vis_cbc_enc"):
            try:
                result = visualize_cbc_text(plaintext, key, iv_hex=iv_hex if iv_hex.strip() else None)
                st.success("Enkripsi CBC berhasil divisualisasikan!")

                st.markdown("### 🔑 Kunci & IV")
                st.code(f"IV  : {result['iv_hex']}", language="text")
                st.code(f"Key : {result['key_bytes_hex']}", language="text")

                st.markdown("### 🔐 Cipher (Hasil Akhir)")
                st.code(result["ciphertext_b64"], language="text")

                st.markdown("### 📦 Detail Per Blok")
                for blk in result["blocks"]:
                    with st.expander(f"🔗 Blok {blk['index']}"):
                        st.code(f"Plaintext : {blk['plaintext_block_hex']}")
                        st.code(f"XOR Input : {blk['xor_input_hex']}")
                        st.code(f"Cipher    : {blk['ciphertext_block_hex']}")

            except Exception as e:
                st.error(e)

    # ============ TAB 4 — VISUALISASI DEKRIPSI ============
    with tab4:
        st.info("⚠ Karena mode CBC chaining, visualisasi dekripsi harus inputkan IV dari Base64!")

        key = st.text_input("Masukkan kunci:", key="cbc_vis_key_dec")
        cipher_b64 = st.text_area("Cipher (Base64):", key="cbc_vis_cipher_dec", height=120)

        if st.button("🔍 Visualisasi CBC (Dekripsi)", key="cbc_btn_vis_dec"):
            try:
                # ekstrak IV + cipher dari base64
                import base64
                raw = base64.b64decode(cipher_b64)
                iv = raw[:16]
                cipher = raw[16:]

                from core.crypto_cbc import _cbc_decrypt_bytes
                plaintext = _cbc_decrypt_bytes(cipher, key, iv)

                st.success("Dekripsi CBC berhasil divisualisasikan!")
                st.markdown("### 🔑 IV dari Cipher")
                st.code(iv.hex(" ").upper(), language="text")

                st.markdown("### 📝 Plaintext Hasil Dekripsi")
                st.code(plaintext.decode("utf-8", errors="replace"), language="text")

            except Exception as e:
                st.error(e)


def cbc_file_ui():
    st.subheader("📁 AES-CBC (File)")

    tab1, tab2 = st.tabs([
        "📁🔐 Enkripsi File CBC",
        "📁🔓 Dekripsi File CBC"
    ])

    key = st.text_input("Masukkan Kunci File CBC:", key="cbc_file_key")

    with tab1:
        file_up = st.file_uploader("Upload File untuk Enkripsi:", key="cbc_file_enc")
        if st.button("Enkripsi File CBC"):
            if file_up:
                import os
                os.makedirs("temp_cbc", exist_ok=True)
                save_path = os.path.join("temp_cbc", file_up.name)
                with open(save_path, "wb") as f:
                    f.write(file_up.read())
                try:
                    out = encrypt_file_cbc(save_path, key)
                    st.success(f"File terenkripsi: {out}")
                except Exception as e:
                    st.error(e)
            else:
                st.warning("Upload file dulu!")

    with tab2:
        file_up = st.file_uploader("Upload File CBC (terenkripsi):", key="cbc_file_dec")
        if st.button("Dekripsi File CBC"):
            if file_up:
                import os
                os.makedirs("temp_cbc", exist_ok=True)
                save_path = os.path.join("temp_cbc", file_up.name)
                with open(save_path, "wb") as f:
                    f.write(file_up.read())
                try:
                    out = decrypt_file_cbc(save_path, key)
                    st.success(f"File berhasil didekripsi: {out}")
                except Exception as e:
                    st.error(e)
            else:
                st.warning("Upload file dulu!")

def lab_cbc_manual_ui():
    st.subheader("🧱 🧪 Laboratorium AES-CBC Manual (1 Blok)")

    st.write(
        "Visualisasi perhitungan **AES-128 CBC** secara manual untuk satu blok data (16 byte), "
        "mulai dari XOR dengan IV hingga seluruh proses round AES. "
        "Mode ini berguna untuk memahami bagaimana *chaining* dalam CBC bekerja."
    )

    # Import manual CBC
    from core.aes_cbc_manual_demo import (
        cbc_manual_encrypt_one_block_from_text,
        cbc_manual_decrypt_one_block_from_hex
    )

    tab_enc, tab_dec = st.tabs(["🔒 Enkripsi CBC Manual", "🔓 Dekripsi CBC Manual"])

    # ================================
    # 🔐 TAB ENKRIPSI MANUAL CBC
    # ================================
    with tab_enc:
        plain = st.text_area(
            "Masukan plaintext (bebas, nanti hanya 16 byte pertama setelah padding):",
            key="cbc_m_plain",
            height=120,
        )
        key = st.text_input(
            "Masukan kunci (string bebas):", type="password", key="cbc_m_key"
        )
        iv_hex = st.text_input(
            "IV (opsional, hex 32 karakter, dipisah spasi atau tidak):",
            key="cbc_m_iv",
            placeholder="contoh: 00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF"
        )

        if st.button("🔍 Analisis Enkripsi CBC Manual", key="cbc_m_btn_enc"):
            try:
                result = cbc_manual_encrypt_one_block_from_text(plain, key, iv_hex)

                st.markdown("### 📌 Blok Plaintext (16 Byte) Setelah Padding")
                st.code(result["padded_plaintext_block_hex"], language="text")

                st.markdown("### 🔑 IV yang Dipakai")
                st.code(result["iv_hex"], language="text")

                st.markdown("### 🔗 XOR (Plaintext ⊕ IV)")
                st.code(result["xor_input_hex"], language="text")

                st.markdown("### 🔐 Cipher Block (Hasil)")
                st.code(result["cipher_block_hex"], language="text")

                # ==========================
                # 🔬 DETAIL ROUND AES
                # ==========================
                aes = result["aes_detail"]
                st.markdown("---")
                st.markdown("## 🔄 Proses Round-by-Round (AES-128 Setelah XOR)")
                st.markdown(f"🔑 **Kunci AES (Normalisasi):** `{aes['key_hex']}`")

                for rd in aes["rounds"]:
                    with st.expander(f"🔷 Round {rd['round']}"):
                        st.info(rd["description"])

                        st.write("**🔑 Round Key:**")
                        st.code(rd["round_key_hex"], language="text")

                        # Kondisional (tidak semua round memiliki step sama)
                        if "after_sub_bytes_hex" in rd:
                            st.write("**🧬 Setelah SubBytes:**")
                            st.code(rd["after_sub_bytes_hex"], language="text")

                        if "after_shift_rows_hex" in rd:
                            st.write("**➡ Setelah ShiftRows:**")
                            st.code(rd["after_shift_rows_hex"], language="text")

                        if "after_mix_columns_hex" in rd:
                            st.write("**🧮 Setelah MixColumns:**")
                            st.code(rd["after_mix_columns_hex"], language="text")

                        st.write("**🔐 Setelah AddRoundKey:**")
                        st.code(rd["after_add_round_key_hex"], language="text")

            except Exception as e:
                st.error(f"Error: {e}")

    # ================================
    # 🔓 TAB DEKRIPSI MANUAL CBC
    # ================================
    with tab_dec:
        st.write(
            "Masukkan **cipher block 16 byte dalam hex** (contoh hasil dari tab enkripsi manual CBC), "
            "bersama kunci dan IV yang sama."
        )

        cipher_hex = st.text_input(
            "Cipher block (16 byte, hex, pisah spasi):",
            key="cbc_m_cipher_hex",
            placeholder="contoh: 13 B6 D2 08 A9 CD F6 5B 06 93 A9 41 E9 35 DC 95"
        )
        key_dec = st.text_input(
            "Masukan kunci (harus sama):", type="password", key="cbc_m_dec_key"
        )
        iv_hex_dec = st.text_input(
            "IV (hex 32 karakter, harus sama):",
            key="cbc_m_iv_dec"
        )

        if st.button("🔍 Analisis Dekripsi CBC Manual", key="cbc_m_btn_dec"):
            try:
                result = cbc_manual_decrypt_one_block_from_hex(cipher_hex, key_dec, iv_hex_dec)

                st.markdown("### 🔐 Cipher Block")
                st.code(result["cipher_block_hex"], language="text")

                st.markdown("### 🔑 IV yang Dipakai")
                st.code(result["iv_hex"], language="text")

                st.markdown("### ↩ Hasil AES⁻¹(C) (Ini Sebelum XOR IV)")
                st.code(result["aes_core_plain_hex"], language="text")

                st.markdown("### 📝 Plaintext Blok Setelah XOR IV")
                st.code(result["final_plaintext_block_hex"], language="text")

                st.success(f"📌 Plaintext Terbaca: {result.get('plaintext_readable','')}")

                # ==========================
                # 🔬 DETAIL ROUND AES (Decrypt)
                # ==========================
                aes = result["aes_detail"]
                st.markdown("---")
                st.markdown("## 🔄 Proses Round-by-Round (Dekripsi AES-128)")
                st.markdown(f"🔑 **Kunci AES (Normalisasi):** `{aes['key_hex']}`")

                for rd in aes["rounds"]:
                    with st.expander(f"🔷 Round Dekripsi {rd['round']}"):
                        st.info(rd["description"])

                        st.write("**🔑 Round Key:**")
                        st.code(rd["round_key_hex"], language="text")

                        if "after_inv_shift_rows_hex" in rd:
                            st.write("**↩ Setelah InvShiftRows:**")
                            st.code(rd["after_inv_shift_rows_hex"], language="text")

                        if "after_inv_sub_bytes_hex" in rd:
                            st.write("**🧬 Setelah InvSubBytes:**")
                            st.code(rd["after_inv_sub_bytes_hex"], language="text")

                        st.write("**🔐 Setelah AddRoundKey:**")
                        st.code(rd["after_add_round_key_hex"], language="text")

                        if "after_inv_mix_columns_hex" in rd:
                            st.write("**🧮 Setelah InvMixColumns:**")
                            st.code(rd["after_inv_mix_columns_hex"], language="text")

            except Exception as e:
                st.error(f"Error: {e}")

