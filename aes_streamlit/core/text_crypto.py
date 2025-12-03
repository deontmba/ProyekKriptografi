# core/text_crypto.py

import base64
from .aes_ecb import encrypt_ecb, decrypt_ecb

from Crypto.Cipher import AES
from .key_utils import normalize_key, pad_pkcs7, AES_BLOCK_SIZE



def encrypt_text(plaintext_str: str, user_key: str) -> str:
    """
    Enkripsi plaintext dalam bentuk string.
    Hasil ciphertext dikembalikan dalam bentuk Base64 (string) agar:
    - aman ditampilkan
    - bisa disalin oleh user
    - tidak berubah seperti bytes mentah

    Proses:
    1. Encode string → bytes
    2. Enkripsi AES-ECB (bytes)
    3. Encode Base64 → string
    """
    if not plaintext_str:
        raise ValueError("Plaintext tidak boleh kosong.")

    plaintext_bytes = plaintext_str.encode("utf-8")
    ciphertext_bytes = encrypt_ecb(plaintext_bytes, user_key)
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")
    return ciphertext_b64


def decrypt_text(ciphertext_b64: str, user_key: str) -> str:
    """
    Dekripsi ciphertext yang diberikan dalam format Base64 (string).
    Output berupa plaintext string UTF-8.

    Proses:
    1. Decode Base64 → bytes ciphertext
    2. AES-ECB decrypt → bytes plaintext
    3. Decode UTF-8 → string
    """
    if not ciphertext_b64:
        raise ValueError("Ciphertext tidak boleh kosong.")

    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Format Base64 tidak valid atau corrupt.")

    plaintext_bytes = decrypt_ecb(ciphertext_bytes, user_key)

    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan teks UTF-8. "
                         "Kemungkinan ciphertext bukan teks terenkripsi.")

    return plaintext_str

def visualize_text_encryption(plaintext_str: str, user_key: str) -> dict:
    """
    Menghasilkan data langkah-demi-langkah enkripsi AES-ECB untuk teks.
    Output berupa dict yang siap ditampilkan di Streamlit.
    """
    if not plaintext_str:
        raise ValueError("Plaintext tidak boleh kosong.")

    # 1. Konversi plaintext ke bytes
    plaintext_bytes = plaintext_str.encode("utf-8")

    # 2. Normalisasi key → AES-128
    key_bytes = normalize_key(user_key, key_size=16)

    # 3. Padding PKCS7
    padded_bytes = pad_pkcs7(plaintext_bytes, block_size=AES_BLOCK_SIZE)

    # 4. Pecah ke blok-blok 16 byte (sebelum enkripsi)
    blocks_plain = [
        padded_bytes[i:i + AES_BLOCK_SIZE]
        for i in range(0, len(padded_bytes), AES_BLOCK_SIZE)
    ]

    # 5. Enkripsi blok-blok (mode ECB)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    cipher_bytes = cipher.encrypt(padded_bytes)

    blocks_cipher = [
        cipher_bytes[i:i + AES_BLOCK_SIZE]
        for i in range(0, len(cipher_bytes), AES_BLOCK_SIZE)
    ]

    # 6. Representasi hex untuk tiap tahap
    def to_hex(b: bytes) -> str:
        return " ".join(f"{x:02X}" for x in b)

    result = {
        "plaintext_str": plaintext_str,
        "plaintext_bytes_hex": to_hex(plaintext_bytes),
        "key_str": user_key,
        "key_bytes_hex": to_hex(key_bytes),
        "blocks": []
    }

    for idx, (pb, cb) in enumerate(zip(blocks_plain, blocks_cipher)):
        result["blocks"].append({
            "index": idx,
            "plaintext_block_hex": to_hex(pb),
            "ciphertext_block_hex": to_hex(cb),
            "size_bytes": len(pb)
        })

    # Base64 akhir juga disertakan agar konsisten dengan encrypt_text
    result["ciphertext_b64"] = base64.b64encode(cipher_bytes).decode("utf-8")

    return result

def visualize_text_decryption(ciphertext_b64: str, user_key: str) -> dict:
    """
    Visualisasi langkah demi langkah dekripsi AES-ECB untuk teks.

    Output berupa dict yang berisi:
    - ciphertext base64
    - ciphertext bytes (hex)
    - key (string + hex)
    - blok-blok ciphertext & plaintext sebelum unpadding
    - info padding PKCS#7
    - plaintext akhir (hex + string)
    """
    if not ciphertext_b64:
        raise ValueError("Ciphertext tidak boleh kosong.")

    # 1. Decode Base64 → ciphertext bytes
    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Format Base64 tidak valid atau corrupt.")

    if len(ciphertext_bytes) == 0:
        raise ValueError("Ciphertext kosong.")

    if len(ciphertext_bytes) % AES_BLOCK_SIZE != 0:
        raise ValueError(
            "Panjang ciphertext bukan kelipatan 16 byte. "
            "Kemungkinan data rusak atau bukan hasil AES-ECB dengan PKCS#7."
        )

    # 2. Normalisasi key → AES-256
    key_bytes = normalize_key(user_key, key_size=16)

    # 3. Pisah ciphertext menjadi blok-blok 16 byte
    blocks_cipher = [
        ciphertext_bytes[i:i + AES_BLOCK_SIZE]
        for i in range(0, len(ciphertext_bytes), AES_BLOCK_SIZE)
    ]

    # 4. Dekripsi seluruh blok (ECB akan memproses per blok)
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded_plain_bytes = cipher.decrypt(ciphertext_bytes)

    # 5. Pisah plaintext (masih termasuk padding) per blok
    blocks_plain_padded = [
        padded_plain_bytes[i:i + AES_BLOCK_SIZE]
        for i in range(0, len(padded_plain_bytes), AES_BLOCK_SIZE)
    ]

    # 6. Deteksi padding PKCS#7
    padding_len = padded_plain_bytes[-1]
    if padding_len <= 0 or padding_len > AES_BLOCK_SIZE:
        # Jika padding aneh → kemungkinan kunci salah
        padding_valid = False
        padding_hex = ""
        plain_no_padding = padded_plain_bytes  # jangan unpad, biarkan apa adanya
    else:
        padding_bytes = padded_plain_bytes[-padding_len:]
        padding_valid = all(b == padding_len for b in padding_bytes)
        padding_hex = " ".join(f"{b:02X}" for b in padding_bytes)
        plain_no_padding = (
            padded_plain_bytes[:-padding_len] if padding_valid else padded_plain_bytes
        )

    # 7. Representasi helper
    def to_hex(b: bytes) -> str:
        return " ".join(f"{x:02X}" for x in b)

    # 8. Coba decode plaintext akhir ke UTF-8
    try:
        plaintext_str = plain_no_padding.decode("utf-8") if padding_valid else ""
    except UnicodeDecodeError:
        plaintext_str = ""

    result = {
        "ciphertext_b64": ciphertext_b64,
        "ciphertext_bytes_hex": to_hex(ciphertext_bytes),
        "key_str": user_key,
        "key_bytes_hex": to_hex(key_bytes),
        "blocks": [],
        "padding_len": int(padding_len),
        "padding_hex": padding_hex,
        "padding_valid": padding_valid,
        "plaintext_bytes_hex": to_hex(plain_no_padding),
        "plaintext_str": plaintext_str,
    }

    for idx, (cb, pb) in enumerate(zip(blocks_cipher, blocks_plain_padded)):
        result["blocks"].append({
            "index": idx,
            "ciphertext_block_hex": to_hex(cb),
            "plaintext_block_hex": to_hex(pb),
            "size_bytes": len(pb),
        })

    return result
