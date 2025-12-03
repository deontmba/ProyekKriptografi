# core/key_utils.py

import hashlib


AES_BLOCK_SIZE = 16  # bytes (128 bit block size AES standar)


def normalize_key(user_key: str, key_size: int = 16) -> bytes:
    """
    Mengubah input kunci dari user (string bebas) menjadi key AES dengan panjang tetap.
    
    Default: key_size = 16 bytes (AES-256)
    Mekanisme:
    - User boleh input password/kunci dalam bentuk teks apa saja.
    - Kita hash dengan SHA-256, lalu dipotong sesuai key_size.
    """
    if not user_key:
        raise ValueError("Kunci tidak boleh kosong.")

    # Ubah ke bytes
    key_bytes = user_key.encode("utf-8")

    # Hash dengan SHA-256 untuk menstabilkan panjang
    hashed = hashlib.sha256(key_bytes).digest()  # 32 bytes

    # Potong sesuai key_size (16, 24, atau 32)
    if key_size not in (16, 24, 32):
        raise ValueError("key_size harus 16, 24, atau 32 byte (AES-128/192/256).")

    return hashed[:key_size]


def pad_pkcs7(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """
    Padding PKCS#7.
    Menambahkan N byte dengan nilai N, di mana N = jumlah padding.
    Contoh:
    - data panjang 14, block_size 16 → butuh 2 byte padding: 0x02 0x02
    """
    if block_size <= 0:
        raise ValueError("block_size harus > 0.")

    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size  # selalu tambah satu blok penuh kalau sudah pas

    padding = bytes([padding_len] * padding_len)
    return data + padding


def unpad_pkcs7(padded_data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:
    """
    Menghapus padding PKCS#7.
    - Membaca byte terakhir → itulah nilai jumlah padding.
    - Validasi semua byte terakhir bernilai sama.
    """
    if not padded_data:
        raise ValueError("Data kosong, tidak bisa di-unpad.")

    if len(padded_data) % block_size != 0:
        raise ValueError("Panjang data tidak kelipatan block_size, kemungkinan bukan PKCS#7 valid.")

    padding_len = padded_data[-1]

    if padding_len <= 0 or padding_len > block_size:
        raise ValueError("Nilai padding tidak valid.")

    # Ambil bagian padding di akhir
    padding = padded_data[-padding_len:]

    # Pastikan semua nilai padding sama
    if any(byte != padding_len for byte in padding):
        raise ValueError("Format padding tidak valid, kemungkinan data rusak atau kunci salah.")

    return padded_data[:-padding_len]

