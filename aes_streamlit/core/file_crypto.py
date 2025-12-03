# core/file_crypto.py

import os
from .aes_ecb import encrypt_ecb, decrypt_ecb
from .key_utils import AES_BLOCK_SIZE


# Lokasi folder penyimpanan output
BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # folder project
ENCRYPTED_DIR = os.path.join(BASE_DIR, "storage/encrypted")
DECRYPTED_DIR = os.path.join(BASE_DIR, "storage/decrypted")


# Pastikan folder output ada
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)


def encrypt_file(input_path: str, user_key: str) -> str:
    """
    Enkripsi file apapun (biner).
    Hasil disimpan pada /storage/encrypted/

    Flow:
    1. Baca file sebagai bytes
    2. Encrypt AES-ECB
    3. Simpan file <nama_asli>.enc
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError("File input tidak ditemukan.")

    # Baca file sebagai biner
    with open(input_path, "rb") as f:
        file_bytes = f.read()

    if not file_bytes:
        raise ValueError("File kosong, tidak bisa dienkripsi.")

    # Enkripsi
    ciphertext = encrypt_ecb(file_bytes, user_key)

    # Nama file output sama tetapi dengan ekstensi .enc
    filename = os.path.basename(input_path) + ".enc"
    output_path = os.path.join(ENCRYPTED_DIR, filename)

    # Simpan
    with open(output_path, "wb") as f:
        f.write(ciphertext)

    return output_path  # untuk ditampilkan di UI / download


def decrypt_file(input_path: str, user_key: str) -> str:
    """
    Dekripsi file terenkripsi (.enc).
    Hasil disimpan kembali di /storage/decrypted/

    Flow:
    1. Baca ciphertext biner
    2. AES-ECB decrypt
    3. Simpan file tanpa .enc
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError("File input tidak ditemukan.")

    # Baca ciphertext sebagai biner
    with open(input_path, "rb") as f:
        ciphertext = f.read()

    if not ciphertext:
        raise ValueError("File terenkripsi kosong atau rusak.")

    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        raise ValueError("Ciphertext tidak kelipatan AES block-size. "
                         "Kemungkinan file rusak atau kunci salah.")

    # Dekripsi
    plaintext_bytes = decrypt_ecb(ciphertext, user_key)

    # Hapus ekstensi .enc
    if input_path.endswith(".enc"):
        filename = os.path.basename(input_path)[:-4]
    else:
        filename = os.path.basename(input_path) + ".dec"

    output_path = os.path.join(DECRYPTED_DIR, filename)

    # Simpan
    with open(output_path, "wb") as f:
        f.write(plaintext_bytes)

    return output_path