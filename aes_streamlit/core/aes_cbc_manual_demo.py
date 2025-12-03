# core/aes_cbc_manual_demo.py

"""
Laboratorium AES-CBC Manual (1 Blok)

File ini melengkapi aes_manual_demo.py dengan mode CBC untuk 1 blok:
- Fokus ke chaining CBC: IV, XOR, dan satu blok AES-128.
- AES-128 di dalamnya menggunakan fungsi manual:
    - aes128_encrypt_block_with_steps
    - aes128_decrypt_block_with_steps

Cocok dipakai di LAB:
- CBC 1 blok (enkripsi): P ⊕ IV → AES → C
- CBC 1 blok (dekripsi): AES⁻¹(C) → (P ⊕ IV) → XOR IV → P
"""

from typing import Dict, Optional

from .key_utils import pad_pkcs7, AES_BLOCK_SIZE
from .aes_manual_demo import (
    aes128_encrypt_block_with_steps,
    aes128_decrypt_block_with_steps,
)


# =========================
#  HELPER
# =========================

def _xor_bytes(b1: bytes, b2: bytes) -> bytes:
    """XOR dua bytes object dengan panjang yang sama."""
    return bytes(x ^ y for x, y in zip(b1, b2))


def _to_hex_spaced(data: bytes) -> str:
    """Representasi bytes → 'AA BB CC DD' (uppercase, dipisah spasi)."""
    return " ".join(f"{b:02X}" for b in data)


def _parse_hex_block(hex_str: str) -> bytes:
    """
    Mengubah string hex dengan spasi/koma menjadi 16 byte.

    Contoh input:
        "13 B6 D2 08 A9 CD F6 5B 06 93 A9 41 E9 35 DC 95"
        "13,B6,D2,08,..."
    """
    parts = [p for p in hex_str.replace(",", " ").split() if p]
    if len(parts) != AES_BLOCK_SIZE:
        raise ValueError(f"Blok hex harus terdiri dari tepat {AES_BLOCK_SIZE} byte.")
    return bytes(int(p, 16) for p in parts)


# =========================
#  CBC MANUAL - ENKRIPSI 1 BLOK (BYTES LEVEL)
# =========================

def encrypt_cbc_one_block_with_steps(
    plaintext_block: bytes,
    key_str: str,
    iv: bytes,
) -> Dict:
    """
    Enkripsi 1 blok CBC secara manual (chaining + AES manual).

    - plaintext_block: HARUS 16 byte (sudah dipadding & diambil blok pertama).
    - key_str: kunci dalam bentuk string (akan diproses oleh AES manual).
    - iv: 16 byte IV.

    Langkah:
      1. XOR_in = P ⊕ IV
      2. AES-128 manual terhadap XOR_in → C
      3. Kembalikan semua detail (IV, XOR, P, C, dan detail round AES).

    Return dict, contoh struktur:
    {
        "mode": "CBC-ENCRYPT-1-BLOCK",
        "block_size": 16,
        "iv_hex": "...",
        "plaintext_block_hex": "...",
        "xor_input_hex": "...",
        "cipher_block_hex": "...",
        "aes_detail": {...}   # hasil aes128_encrypt_block_with_steps
    }
    """
    if len(plaintext_block) != AES_BLOCK_SIZE:
        raise ValueError(f"plaintext_block harus 16 byte, dapat {len(plaintext_block)}.")
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError(f"IV harus 16 byte, dapat {len(iv)}.")

    # 1. XOR plaintext dengan IV
    xor_in = _xor_bytes(plaintext_block, iv)

    # 2. Encrypt XOR_in dengan AES manual 1 blok
    aes_result = aes128_encrypt_block_with_steps(xor_in, key_str)
    # aes_result seharusnya berisi:
    #  - "plaintext_block_hex"  → di sini = XOR_in
    #  - "cipher_block_hex"     → C
    #  - "key_hex"
    #  - "rounds", dll.

    cipher_block_hex = aes_result.get("cipher_block_hex", "")
    xor_input_hex = aes_result.get("plaintext_block_hex", _to_hex_spaced(xor_in))

    result: Dict = {
        "mode": "CBC-ENCRYPT-1-BLOCK",
        "block_size": AES_BLOCK_SIZE,
        "iv_hex": _to_hex_spaced(iv),
        "plaintext_block_hex": _to_hex_spaced(plaintext_block),
        "xor_input_hex": xor_input_hex,
        "cipher_block_hex": cipher_block_hex,
        "aes_detail": aes_result,
    }
    return result


# =========================
#  CBC MANUAL - DEKRIPSI 1 BLOK (BYTES LEVEL)
# =========================

def decrypt_cbc_one_block_with_steps(
    cipher_block: bytes,
    key_str: str,
    iv: bytes,
) -> Dict:
    """
    Dekripsi 1 blok CBC secara manual (chaining + AES manual).

    CBC dekripsi:
      1. AES⁻¹(C) = P ⊕ IV
      2. P = (AES⁻¹(C)) ⊕ IV

    - cipher_block: 16 byte
    - key_str: string kunci
    - iv: 16 byte IV

    Return dict:
    {
        "mode": "CBC-DECRYPT-1-BLOCK",
        "block_size": 16,
        "iv_hex": "...",
        "cipher_block_hex": "...",
        "aes_core_plain_hex": "...",   # hasil AES⁻¹(C) = P ⊕ IV
        "final_plaintext_block_hex": "...", # P
        "plaintext_readable": "...",
        "aes_detail": {...},          # hasil aes128_decrypt_block_with_steps
    }
    """
    if len(cipher_block) != AES_BLOCK_SIZE:
        raise ValueError(f"cipher_block harus 16 byte, dapat {len(cipher_block)}.")
    if len(iv) != AES_BLOCK_SIZE:
        raise ValueError(f"IV harus 16 byte, dapat {len(iv)}.")

    # 1. AES⁻¹(C) dengan AES manual
    aes_result = aes128_decrypt_block_with_steps(cipher_block, key_str)
    # Untuk ECB manual, aes_result["plaintext_block_hex"] = plaintext_block_hex.
    # Dalam konteks CBC, ini sebenarnya sama dengan P ⊕ IV (hasil AES⁻¹ sebelum XOR IV).

    aes_core_plain_hex = aes_result.get("plaintext_block_hex", "")
    # Konversi hex → bytes untuk XOR dengan IV
    if aes_core_plain_hex:
        parts = [p for p in aes_core_plain_hex.replace(",", " ").split() if p]
        if len(parts) != AES_BLOCK_SIZE:
            raise ValueError(
                f"plaintext_block_hex dari AES manual tidak 16 byte, dapat {len(parts)}."
            )
        aes_core_plain_bytes = bytes(int(p, 16) for p in parts)
    else:
        # fallback: gunakan langsung hasil decrypt (walau mestinya tidak terjadi)
        aes_core_plain_bytes = _xor_bytes(cipher_block, iv)

    # 2. P = (AES⁻¹(C)) ⊕ IV
    final_plain_block = _xor_bytes(aes_core_plain_bytes, iv)

    # Coba decode plaintext terbaca (UTF-8, ignore error)
    try:
        plaintext_readable = final_plain_block.decode("utf-8", errors="ignore")
    except Exception:
        plaintext_readable = ""

    result: Dict = {
        "mode": "CBC-DECRYPT-1-BLOCK",
        "block_size": AES_BLOCK_SIZE,
        "iv_hex": _to_hex_spaced(iv),
        "cipher_block_hex": _to_hex_spaced(cipher_block),
        "aes_core_plain_hex": _to_hex_spaced(aes_core_plain_bytes),
        "final_plaintext_block_hex": _to_hex_spaced(final_plain_block),
        "plaintext_readable": plaintext_readable,
        "aes_detail": aes_result,
    }
    return result


# =========================
#  WRAPPER UNTUK UI (TEXT LEVEL)
# =========================

def cbc_manual_encrypt_one_block_from_text(
    plaintext_str: str,
    key_str: str,
    iv_hex: Optional[str] = None,
) -> Dict:
    """
    Wrapper untuk LAB:
    - Input: plaintext string (bebas), key string, IV dalam bentuk hex (opsional).
    - Proses:
        1. plaintext → bytes
        2. padding PKCS#7 → ambil 16 byte pertama
        3. jika IV tidak diberikan, gunakan 16 byte nol (untuk demo deterministik)
        4. panggil encrypt_cbc_one_block_with_steps(...)
    """
    if not plaintext_str:
        raise ValueError("Plaintext tidak boleh kosong.")

    plain_bytes = plaintext_str.encode("utf-8")
    padded = pad_pkcs7(plain_bytes, block_size=AES_BLOCK_SIZE)
    block = padded[:AES_BLOCK_SIZE]

    if iv_hex:
        try:
            raw_iv = bytes.fromhex(iv_hex.replace(" ", ""))
        except ValueError:
            raise ValueError("Format IV hex tidak valid.")
        if len(raw_iv) != AES_BLOCK_SIZE:
            raise ValueError(f"IV (dari hex) harus {AES_BLOCK_SIZE} byte.")
        iv = raw_iv
    else:
        # Untuk LAB, IV default = 16 byte nol (supaya deterministik)
        iv = bytes(AES_BLOCK_SIZE)

    result = encrypt_cbc_one_block_with_steps(block, key_str, iv)
    # Tambahkan info plaintext asli
    result["plaintext_input"] = plaintext_str
    result["padded_plaintext_block_hex"] = _to_hex_spaced(block)
    return result


def cbc_manual_decrypt_one_block_from_hex(
    cipher_block_hex: str,
    key_str: str,
    iv_hex: Optional[str] = None,
) -> Dict:
    """
    Wrapper untuk LAB:
    - Input: cipher block hex (16 byte), key string, IV hex.
    - Proses:
        1. parse hex → 16 byte cipher_block
        2. parse IV hex → 16 byte (atau nol jika tidak diberikan)
        3. panggil decrypt_cbc_one_block_with_steps(...)
    """
    if not cipher_block_hex:
        raise ValueError("Cipher block hex tidak boleh kosong.")

    cipher_block = _parse_hex_block(cipher_block_hex)

    if iv_hex:
        try:
            raw_iv = bytes.fromhex(iv_hex.replace(" ", ""))
        except ValueError:
            raise ValueError("Format IV hex tidak valid.")
        if len(raw_iv) != AES_BLOCK_SIZE:
            raise ValueError(f"IV (dari hex) harus {AES_BLOCK_SIZE} byte.")
        iv = raw_iv
    else:
        iv = bytes(AES_BLOCK_SIZE)

    result = decrypt_cbc_one_block_with_steps(cipher_block, key_str, iv)
    return result
