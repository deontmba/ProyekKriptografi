# core/aes_ecb.py

from Crypto.Cipher import AES
from .key_utils import normalize_key, pad_pkcs7, unpad_pkcs7, AES_BLOCK_SIZE


def encrypt_ecb(plaintext: bytes, user_key: str) -> bytes:
    """
    Enkripsi data (bytes) menggunakan AES-ECB.
    
    Langkah:
    1. Normalisasi kunci user → key AES 16/24/32 byte (default: 32/AES-256)
    2. Lakukan padding PKCS#7 supaya panjang data kelipatan 16
    3. Enkripsi dengan AES.MODE_ECB
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext harus bertipe bytes.")

    if plaintext == b"":
        raise ValueError("plaintext tidak boleh kosong.")

    # Normalisasi key (AES-256)
    key = normalize_key(user_key, key_size=16)

    # Padding
    padded = pad_pkcs7(plaintext, block_size=AES_BLOCK_SIZE)

    # Cipher AES ECB
    cipher = AES.new(key, AES.MODE_ECB)

    # Enkripsi
    ciphertext = cipher.encrypt(padded)
    return ciphertext


def decrypt_ecb(ciphertext: bytes, user_key: str) -> bytes:
    """
    Dekripsi data (bytes) menggunakan AES-ECB.
    
    Langkah:
    1. Normalisasi kunci user → key AES 16/24/32 byte (harus sama dengan saat enkripsi)
    2. Deskripsi dengan AES.MODE_ECB
    3. Hapus padding PKCS#7 → dapatkan plaintext asli
    """
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext harus bertipe bytes.")

    if ciphertext == b"":
        raise ValueError("ciphertext tidak boleh kosong.")

    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError(
            "Panjang ciphertext harus kelipatan block size (16 byte). "
            "Kemungkinan data rusak atau bukan hasil AES-ECB dengan PKCS#7."
        )

    # Normalisasi key (harus sama dengan yang dipakai saat enkripsi)
    key = normalize_key(user_key, key_size=16)

    # Cipher AES ECB
    cipher = AES.new(key, AES.MODE_ECB)

    # Dekripsi
    padded_plaintext = cipher.decrypt(ciphertext)

    # Unpad
    plaintext = unpad_pkcs7(padded_plaintext, block_size=AES_BLOCK_SIZE)
    return plaintext
