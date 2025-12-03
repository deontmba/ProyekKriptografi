# core/crypto_cbc.py

import os
import base64
from typing import List, Dict, Tuple

from Crypto.Cipher import AES
from .key_utils import (
    normalize_key,
    pad_pkcs7,
    unpad_pkcs7,
    AES_BLOCK_SIZE,
)

from typing import Optional


# =========================
#  HELPER INTERNAL
# =========================

def _xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """
    XOR dua bytes object dengan panjang yang sama.
    """
    return bytes(x ^ y for x, y in zip(b1, b2))


def _split_blocks(data: bytes, block_size: int = AES_BLOCK_SIZE) -> List[bytes]:
    """
    Memecah data menjadi blok-blok dengan ukuran block_size.
    """
    return [
        data[i: i + block_size]
        for i in range(0, len(data), block_size)
    ]


def _to_hex_spaced(b: bytes) -> str:
    """
    Representasi bytes → string hex dengan spasi, misal: "6A 2B FF 01".
    """
    return " ".join(f"{x:02X}" for x in b)


# =========================
#  INTI CBC (BYTES LEVEL)
# =========================

def _cbc_encrypt_bytes(
    plaintext: bytes,
    user_key: str,
    iv: bytes,
    *,
    return_debug: bool = False,
) -> Tuple[bytes, Dict]:
    """
    Enkripsi AES-128 CBC level bytes, dengan padding PKCS#7.

    - plaintext: bytes bebas (belum dipadding)
    - user_key: kunci dalam bentuk string (akan dinormalisasi)
    - iv: 16 byte IV
    - return_debug: jika True, akan mengembalikan info blok untuk visualisasi

    Return:
    - ciphertext_bytes: murni C[0]||C[1]||... (TANPA IV di depan)
    - debug_info: dict berisi key, iv, blok, dll (untuk visualisasi)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("Plaintext harus berupa bytes.")

    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("IV untuk CBC harus 16 byte (AES-128 block size).")

    # 1. Normalisasi kunci → AES-128 (16 byte)
    key_bytes = normalize_key(user_key, key_size=16)

    # 2. Padding plaintext
    padded_plain = pad_pkcs7(plaintext, block_size=AES_BLOCK_SIZE)

    # 3. Siapkan cipher AES-ECB (CBC kita bangun manual)
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    # 4. Bagi menjadi blok 16 byte
    plain_blocks = _split_blocks(padded_plain, AES_BLOCK_SIZE)

    cipher_blocks: List[bytes] = []
    prev_cipher = iv

    blocks_debug: List[Dict] = []

    # 5. Proses CBC: C[i] = AES( P[i] ⊕ C[i-1] ), C[-1] = IV
    for idx, block in enumerate(plain_blocks):
        xor_in = _xor_bytes(block, prev_cipher)
        c_block = cipher.encrypt(xor_in)
        cipher_blocks.append(c_block)

        if return_debug:
            blocks_debug.append({
                "index": idx,
                "plaintext_block_hex": _to_hex_spaced(block),
                "prev_cipher_hex": _to_hex_spaced(prev_cipher),
                "xor_input_hex": _to_hex_spaced(xor_in),
                "ciphertext_block_hex": _to_hex_spaced(c_block),
                "size_bytes": len(block),
            })

        prev_cipher = c_block

    ciphertext_bytes = b"".join(cipher_blocks)

    debug_info = {}
    if return_debug:
        debug_info = {
            "mode": "CBC",
            "block_size": AES_BLOCK_SIZE,
            "key_bytes": key_bytes,
            "key_bytes_hex": _to_hex_spaced(key_bytes),
            "iv": iv,
            "iv_hex": _to_hex_spaced(iv),
            "padded_plaintext": padded_plain,
            "padded_plaintext_hex": _to_hex_spaced(padded_plain),
            "blocks": blocks_debug,
        }

    return ciphertext_bytes, debug_info


def _cbc_decrypt_bytes(
    ciphertext: bytes,
    user_key: str,
    iv: bytes,
) -> bytes:
    """
    Dekripsi AES-128 CBC level bytes, dengan unpadding PKCS#7.

    - ciphertext: bytes yang panjangnya kelipatan 16 (TANPA IV di depan)
    - user_key: kunci string (dinormalisasi)
    - iv: 16 byte IV

    Return:
    - plaintext (setelah unpad) sebagai bytes.
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("Ciphertext harus berupa bytes.")

    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError("IV untuk CBC harus 16 byte (AES-128 block size).")

    if len(ciphertext) == 0 or len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext CBC harus kelipatan 16 byte dan tidak boleh kosong.")

    key_bytes = normalize_key(user_key, key_size=16)
    cipher = AES.new(key_bytes, AES.MODE_ECB)

    cipher_blocks = _split_blocks(ciphertext, AES_BLOCK_SIZE)
    prev_cipher = iv
    plain_padded_parts: List[bytes] = []

    for c_block in cipher_blocks:
        decrypted = cipher.decrypt(c_block)
        p_block = _xor_bytes(decrypted, prev_cipher)
        plain_padded_parts.append(p_block)
        prev_cipher = c_block

    padded_plain = b"".join(plain_padded_parts)
    plaintext = unpad_pkcs7(padded_plain, block_size=AES_BLOCK_SIZE)
    return plaintext


# =========================
#  FUNGSI PUBLIK - TEKS
# =========================

def encrypt_text_cbc(plaintext_str: str, user_key: str) -> str:
    """
    Enkripsi plaintext (string) menggunakan AES-128 CBC.

    Hasil akhir:
    - Ciphertext yang dikembalikan berupa Base64 (string)
    - Format internal:  [IV (16 byte)] || [C[0] || C[1] || ...]
      kemudian di-Base64-kan.
    """
    if not plaintext_str:
        raise ValueError("Plaintext tidak boleh kosong.")

    # Plaintext → bytes
    plaintext_bytes = plaintext_str.encode("utf-8")

    # Generate IV random 16 byte
    iv = os.urandom(AES_BLOCK_SIZE)

    # Enkripsi CBC
    cipher_bytes, _ = _cbc_encrypt_bytes(
        plaintext_bytes,
        user_key,
        iv,
        return_debug=False,
    )

    # Gabungkan: IV || ciphertext
    combined = iv + cipher_bytes

    # Encode Base64
    ciphertext_b64 = base64.b64encode(combined).decode("utf-8")
    return ciphertext_b64


def decrypt_text_cbc(ciphertext_b64: str, user_key: str) -> str:
    """
    Dekripsi ciphertext AES-128 CBC yang diberikan dalam format Base64 (string).

    Asumsi format internal:
    - Base64 dari [IV (16 byte)] || [C[0] || C[1] || ...]

    Output:
    - plaintext string UTF-8
    """
    if not ciphertext_b64:
        raise ValueError("Ciphertext tidak boleh kosong.")

    # Decode Base64 → bytes: [IV||ciphertext]
    try:
        combined = base64.b64decode(ciphertext_b64)
    except Exception:
        raise ValueError("Format Base64 tidak valid atau corrupt.")

    if len(combined) < AES_BLOCK_SIZE * 2:
        # minimal: 16 byte IV + 16 byte 1 blok ciphertext
        raise ValueError("Data terlalu pendek untuk format CBC (butuh IV + minimal 1 blok).")

    iv = combined[:AES_BLOCK_SIZE]
    ciphertext = combined[AES_BLOCK_SIZE:]

    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext tidak kelipatan AES block-size. "
                         "Kemungkinan data rusak atau kunci salah.")

    # Dekripsi CBC
    try:
        plaintext_bytes = _cbc_decrypt_bytes(ciphertext, user_key, iv)
    except ValueError as e:
        # Wrap error padding / format supaya lebih ramah di UI
        raise ValueError(f"Dekripsi CBC gagal: {e}")

    # Decode UTF-8
    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Hasil dekripsi bukan teks UTF-8. "
            "Kemungkinan ciphertext bukan teks terenkripsi atau kunci salah."
        )

    return plaintext_str



def visualize_cbc_text(plaintext_str: str, user_key: str, iv_hex: Optional[str] = None) -> dict:

    """
    Visualisasi langkah demi langkah enkripsi AES-128 CBC untuk teks.

    Fokus:
    - Menampilkan IV
    - Menampilkan XOR(P[i], IV/C[i-1]) per blok
    - Menampilkan hasil AES encrypt tiap blok

    Tidak membongkar SubBytes/ShiftRows/MixColumns (itu sudah di lab AES ECB manual).

    Output dict siap dipakai UI, kira-kira berisi:
    - plaintext_str
    - plaintext_bytes_hex
    - key_str, key_bytes_hex
    - iv_hex
    - padded_plaintext_hex
    - blocks: list per blok {index, plaintext_block_hex, prev_cipher_hex,
                             xor_input_hex, ciphertext_block_hex, size_bytes}
    - ciphertext_hex (tanpa IV)
    - ciphertext_b64 (dengan IV di depan)
    """
    if not plaintext_str:
        raise ValueError("Plaintext tidak boleh kosong.")

    # 1. Plaintext → bytes
    plaintext_bytes = plaintext_str.encode("utf-8")

    # 2. Normalisasi key
    key_bytes = normalize_key(user_key, key_size=16)

    # 3. Siapkan IV
    if iv_hex:
        try:
            iv = bytes.fromhex(iv_hex.replace(" ", ""))
        except ValueError:
            raise ValueError("Format IV hex tidak valid.")
        if len(iv) != AES_BLOCK_SIZE:
            raise ValueError("IV (dari hex) harus 16 byte.")
    else:
        iv = os.urandom(AES_BLOCK_SIZE)

    # 4. Enkripsi CBC dengan debug
    cipher_bytes, debug_info = _cbc_encrypt_bytes(
        plaintext_bytes,
        user_key,
        iv,
        return_debug=True,
    )

    # 5. Gabungkan IV + ciphertext untuk bentuk akhir Base64
    combined = iv + cipher_bytes
    ciphertext_b64 = base64.b64encode(combined).decode("utf-8")

    result = {
        "mode": "CBC",
        "block_size": AES_BLOCK_SIZE,
        "plaintext_str": plaintext_str,
        "plaintext_bytes_hex": _to_hex_spaced(plaintext_bytes),
        "key_str": user_key,
        "key_bytes_hex": _to_hex_spaced(key_bytes),
        "iv_hex": _to_hex_spaced(iv),
        "padded_plaintext_hex": debug_info.get("padded_plaintext_hex", ""),
        "ciphertext_hex": _to_hex_spaced(cipher_bytes),
        "ciphertext_b64": ciphertext_b64,
        "blocks": debug_info.get("blocks", []),
    }

    return result


# =========================
#  FUNGSI PUBLIK - FILE
# =========================

# Lokasi folder penyimpanan output (disamakan dengan file_crypto.py)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # folder project
ENCRYPTED_DIR = os.path.join(BASE_DIR, "storage/encrypted")
DECRYPTED_DIR = os.path.join(BASE_DIR, "storage/decrypted")

os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)


def encrypt_file_cbc(input_path: str, user_key: str) -> str:
    """
    Enkripsi file biner menggunakan AES-128 CBC.

    Format file terenkripsi:
    - 16 byte pertama : IV
    - sisanya         : ciphertext CBC (kelipatan 16 byte)

    Output:
    - Path file terenkripsi yang disimpan di /storage/encrypted/
    - Nama file: <nama_asli>.cbc
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError("File input tidak ditemukan.")

    # Baca file sebagai bytes
    with open(input_path, "rb") as f:
        file_bytes = f.read()

    # Generate IV random
    iv = os.urandom(AES_BLOCK_SIZE)

    # Enkripsi CBC (tanpa perlu debug, supaya hemat memori)
    cipher_bytes, _ = _cbc_encrypt_bytes(
        file_bytes,
        user_key,
        iv,
        return_debug=False,
    )

    combined = iv + cipher_bytes

    # Nama file output: <nama_asli>.cbc
    filename = os.path.basename(input_path) + ".cbc"
    output_path = os.path.join(ENCRYPTED_DIR, filename)

    with open(output_path, "wb") as f:
        f.write(combined)

    return output_path


def decrypt_file_cbc(input_path: str, user_key: str) -> str:
    """
    Dekripsi file AES-128 CBC yang disimpan dengan format:

    [IV (16 byte)] || [ciphertext CBC]

    Output:
    - File hasil dekripsi disimpan di /storage/decrypted/
    - Nama file:
        * jika nama input diakhiri ".cbc" → ekstensi ".cbc" dihapus
        * jika tidak                        → tambahkan ".dec"
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError("File terenkripsi tidak ditemukan.")

    with open(input_path, "rb") as f:
        data = f.read()

    if len(data) < AES_BLOCK_SIZE * 2:
        raise ValueError("File terlalu pendek untuk format CBC (minimal IV + 1 blok ciphertext).")

    iv = data[:AES_BLOCK_SIZE]
    ciphertext = data[AES_BLOCK_SIZE:]

    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext dalam file tidak kelipatan block size. "
                         "Kemungkinan file rusak atau kunci salah.")

    # Dekripsi CBC
    try:
        plaintext_bytes = _cbc_decrypt_bytes(ciphertext, user_key, iv)
    except ValueError as e:
        raise ValueError(f"Dekripsi file CBC gagal: {e}")

    # Tentukan nama output
    if input_path.endswith(".cbc"):
        filename = os.path.basename(input_path)[:-4]
    else:
        filename = os.path.basename(input_path) + ".dec"

    output_path = os.path.join(DECRYPTED_DIR, filename)

    with open(output_path, "wb") as f:
        f.write(plaintext_bytes)

    return output_path
