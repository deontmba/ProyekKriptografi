# core/aes_manual_demo.py
"""
Demo AES-128 manual untuk 1 blok (16 byte).

Tujuan:
- Menunjukkan langkah internal AES: SubBytes, ShiftRows, MixColumns, AddRoundKey
- Tanpa menggunakan library Crypto.Cipher.AES
- Hanya untuk DEMO / visualisasi, bukan untuk enkripsi produksi (yang tetap pakai aes_ecb.py)
"""

from .key_utils import normalize_key, AES_BLOCK_SIZE


# =========================
#  KONSTANTA S-BOX & RCON
# =========================

S_BOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# Inverse S-Box untuk dekripsi
INV_S_BOX = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
]



# =========================
#  HELPER FUNGSI AES
# =========================

def _sub_word(word: bytes) -> bytes:
    return bytes(S_BOX[b] for b in word)


def _rot_word(word: bytes) -> bytes:
    return word[1:] + word[:1]


def _key_expansion_128(key: bytes):
    """
    Key expansion untuk AES-128.
    Input: 16 byte
    Output: list 44 word (4 byte), dibagi per 4 word = 11 round key
    """
    Nk = 4
    Nb = 4
    Nr = 10
    w = [b"\x00\x00\x00\x00"] * (Nb * (Nr + 1))

    # 4 word pertama = key awal
    w[0:4] = [key[0:4], key[4:8], key[8:12], key[12:16]]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = bytes(
                a ^ b
                for a, b in zip(
                    _sub_word(_rot_word(temp)),
                    bytes([RCON[i // Nk], 0x00, 0x00, 0x00]),
                )
            )
        w[i] = bytes(a ^ b for a, b in zip(w[i - Nk], temp))
    return w  # panjang 44 word


def _bytes_to_state(block: bytes):
    """
    Konversi 16 byte menjadi state 4x4 (baris x kolom) dalam column-major
    state[r][c] = byte pada baris r, kolom c.
    """
    assert len(block) == 16
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]


def _state_to_bytes(state):
    out = bytearray(16)
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = state[r][c]
    return bytes(out)


def _sub_bytes(state):
    return [[S_BOX[b] for b in row] for row in state]


def _shift_rows(state):
    new = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new[r][c] = state[r][(c + r) % 4]
    return new


def _gmul(a, b):
    """
    Perkalian di GF(2^8) untuk MixColumns.
    """
    p = 0
    a &= 0xFF
    b &= 0xFF
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        _gmul(a0, 2) ^ _gmul(a1, 3) ^ a2 ^ a3,
        a0 ^ _gmul(a1, 2) ^ _gmul(a2, 3) ^ a3,
        a0 ^ a1 ^ _gmul(a2, 2) ^ _gmul(a3, 3),
        _gmul(a0, 3) ^ a1 ^ a2 ^ _gmul(a3, 2),
    ]


def _mix_columns(state):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mc = _mix_single_column(col)
        for r in range(4):
            new[r][c] = mc[r]
    return new


def _add_round_key(state, round_key_words):
    """
    round_key_words: list of 4 word (masing2 4 byte) untuk kolom 0..3
    """
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        word = round_key_words[c]
        for r in range(4):
            new[r][c] = state[r][c] ^ word[r]
    return new


def _to_hex_bytes(b: bytes) -> str:
    return " ".join(f"{x:02X}" for x in b)


def _to_hex_state(state) -> str:
    """
    Representasi state (4x4) dalam bentuk 16 byte hex (urut column-major).
    """
    return _to_hex_bytes(_state_to_bytes(state))

def _inv_sub_bytes(state):
    return [[INV_S_BOX[b] for b in row] for row in state]


def _inv_shift_rows(state):
    new = [[0] * 4 for _ in range(4)]
    for r in range(4):
        for c in range(4):
            new[r][(c + r) % 4] = state[r][c]  # shift kanan (kebalikan ShiftRows)
    return new


def _inv_mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        _gmul(a0, 0x0E) ^ _gmul(a1, 0x0B) ^ _gmul(a2, 0x0D) ^ _gmul(a3, 0x09),
        _gmul(a0, 0x09) ^ _gmul(a1, 0x0E) ^ _gmul(a2, 0x0B) ^ _gmul(a3, 0x0D),
        _gmul(a0, 0x0D) ^ _gmul(a1, 0x09) ^ _gmul(a2, 0x0E) ^ _gmul(a3, 0x0B),
        _gmul(a0, 0x0B) ^ _gmul(a1, 0x0D) ^ _gmul(a2, 0x09) ^ _gmul(a3, 0x0E),
    ]


def _inv_mix_columns(state):
    new = [[0] * 4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        mc = _inv_mix_single_column(col)
        for r in range(4):
            new[r][c] = mc[r]
    return new



# =========================
#  FUNGSI UTAMA DEMO
# =========================

def aes128_encrypt_block_with_steps(block: bytes, user_key: str) -> dict:
    """
    Enkripsi 1 blok (16 byte) AES-128 secara manual (tanpa Crypto library),
    dan mengembalikan semua langkah per round untuk visualisasi di UI.

    Param:
        block: 16 byte plaintext (setelah padding, kalau perlu)
        user_key: string kunci dari user, akan dinormalisasi ke 16 byte (AES-128)

    Return dict kira-kira:
    {
      "plaintext_block_hex": ...,
      "key_hex": ...,
      "rounds": [
         {
           "round": 0,
           "round_key_hex": ...,
           "after_add_round_key_hex": ...
         },
         {
           "round": 1,
           "round_key_hex": ...,
           "after_sub_bytes_hex": ...,
           "after_shift_rows_hex": ...,
           "after_mix_columns_hex": ...,
           "after_add_round_key_hex": ...
         },
         ...
         {
           "round": 10,
           "round_key_hex": ...,
           "after_sub_bytes_hex": ...,
           "after_shift_rows_hex": ...,
           "after_add_round_key_hex": ...
         }
      ],
      "cipher_block_hex": ...
    }
    """
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError("Demo manual ini hanya untuk 1 blok (16 byte).")

    # Normalisasi key user menjadi 16 byte (AES-128)
    key_bytes = normalize_key(user_key, key_size=16)

    # Key expansion
    w = _key_expansion_128(key_bytes)  # 44 word
    Nr = 10

    # Round keys (per 4 word)
    round_keys = [w[i * 4:(i + 1) * 4] for i in range(Nr + 1)]

    # State awal
    state = _bytes_to_state(block)

    result = {
        "plaintext_block_hex": _to_hex_bytes(block),
        "key_hex": _to_hex_bytes(key_bytes),
        "rounds": [],
    }

    # ===== Round 0: AddRoundKey =====
    rk0_state = _add_round_key(state, round_keys[0])
    result["rounds"].append({
        "round": 0,
        "description": "Round 0 (AddRoundKey awal): plaintext XOR dengan key awal.",
        "round_key_hex": " | ".join(_to_hex_bytes(wd) for wd in round_keys[0]),
        "after_add_round_key_hex": _to_hex_state(rk0_state),
    })

    state = rk0_state

    # ===== Round 1..9 =====
    for rnd in range(1, Nr):
        # SubBytes
        sb_state = _sub_bytes(state)
        # ShiftRows
        sr_state = _shift_rows(sb_state)
        # MixColumns
        mc_state = _mix_columns(sr_state)
        # AddRoundKey
        ark_state = _add_round_key(mc_state, round_keys[rnd])

        result["rounds"].append({
            "round": rnd,
            "description": (
                f"Round {rnd}: SubBytes → ShiftRows → MixColumns → AddRoundKey. "
                "Setiap round meningkatkan konfusi dan difusi pada state."
            ),
            "round_key_hex": " | ".join(_to_hex_bytes(wd) for wd in round_keys[rnd]),
            "after_sub_bytes_hex": _to_hex_state(sb_state),
            "after_shift_rows_hex": _to_hex_state(sr_state),
            "after_mix_columns_hex": _to_hex_state(mc_state),
            "after_add_round_key_hex": _to_hex_state(ark_state),
        })

        state = ark_state

    # ===== Round 10 (tanpa MixColumns) =====
    sb_state = _sub_bytes(state)
    sr_state = _shift_rows(sb_state)
    ark_state = _add_round_key(sr_state, round_keys[Nr])

    cipher_block = _state_to_bytes(ark_state)

    result["rounds"].append({
        "round": Nr,
        "description": (
            "Round 10 (final): SubBytes → ShiftRows → AddRoundKey (tanpa MixColumns). "
            "Hasilnya adalah ciphertext blok final."
        ),
        "round_key_hex": " | ".join(_to_hex_bytes(wd) for wd in round_keys[Nr]),
        "after_sub_bytes_hex": _to_hex_state(sb_state),
        "after_shift_rows_hex": _to_hex_state(sr_state),
        "after_add_round_key_hex": _to_hex_state(ark_state),
    })

    result["cipher_block_hex"] = _to_hex_bytes(cipher_block)

    return result

def aes128_decrypt_block_with_steps(block: bytes, user_key: str) -> dict:
    """
    Dekripsi 1 blok (16 byte) AES-128 secara manual, untuk demo.
    Kebalikan dari aes128_encrypt_block_with_steps.

    Return dict mirip:
    {
      "cipher_block_hex": ...,
      "key_hex": ...,
      "rounds": [...],
      "plaintext_block_hex": ...
    }
    """
    if len(block) != AES_BLOCK_SIZE:
        raise ValueError("Demo manual ini hanya untuk 1 blok (16 byte).")

    # Normalisasi key user menjadi 16 byte (AES-128)
    key_bytes = normalize_key(user_key, key_size=16)

    # Key expansion sama seperti enkripsi
    w = _key_expansion_128(key_bytes)
    Nr = 10
    round_keys = [w[i * 4:(i + 1) * 4] for i in range(Nr + 1)]

    # State awal = cipher block
    state = _bytes_to_state(block)

    result = {
        "cipher_block_hex": _to_hex_bytes(block),
        "key_hex": _to_hex_bytes(key_bytes),
        "rounds": [],
    }

    # ===== Round 0 (dari sisi dekripsi): AddRoundKey dengan round key terakhir =====
    ark0_state = _add_round_key(state, round_keys[Nr])
    result["rounds"].append({
        "round": 0,
        "description": (
            "Langkah awal dekripsi: state ciphertext dikalikan (XOR) dengan round key terakhir "
            "(kebalikan dari AddRoundKey di round final enkripsi)."
        ),
        "round_key_hex": " | ".join(_to_hex_bytes(wd) for wd in round_keys[Nr]),
        "after_add_round_key_hex": _to_hex_state(ark0_state),
    })
    state = ark0_state

    # ===== Round 1..9 (dari atas ke bawah: Nr-1 .. 1) =====
    for r in range(Nr - 1, 0, -1):
        # InvShiftRows
        isr_state = _inv_shift_rows(state)
        # InvSubBytes
        isb_state = _inv_sub_bytes(isr_state)
        # AddRoundKey
        ark_state = _add_round_key(isb_state, round_keys[r])
        # InvMixColumns
        imc_state = _inv_mix_columns(ark_state)

        result["rounds"].append({
            "round": Nr - r,  # urutan logis: 1,2,...,9
            "description": (
                "Round dekripsi: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns. "
                "Ini membalik efek round enkripsi sebelumnya."
            ),
            "round_key_hex": " | ".join(_to_hex_bytes(wd) for wd in round_keys[r]),
            "after_inv_shift_rows_hex": _to_hex_state(isr_state),
            "after_inv_sub_bytes_hex": _to_hex_state(isb_state),
            "after_add_round_key_hex": _to_hex_state(ark_state),
            "after_inv_mix_columns_hex": _to_hex_state(imc_state),
        })

        state = imc_state

    # ===== Round terakhir dekripsi (kebalikan round 0 enkripsi): InvShiftRows → InvSubBytes → AddRoundKey (key 0) =====
    isr_state = _inv_shift_rows(state)
    isb_state = _inv_sub_bytes(isr_state)
    ark_state = _add_round_key(isb_state, round_keys[0])

    plain_block = _state_to_bytes(ark_state)

    result["rounds"].append({
        "round": 10,
        "description": (
            "Round dekripsi terakhir: InvShiftRows → InvSubBytes → AddRoundKey dengan key awal. "
            "Ini menghasilkan kembali blok plaintext (termasuk padding)."
        ),
        "round_key_hex": " | ".join(_to_hex_bytes(wd) for wd in round_keys[0]),
        "after_inv_shift_rows_hex": _to_hex_state(isr_state),
        "after_inv_sub_bytes_hex": _to_hex_state(isb_state),
        "after_add_round_key_hex": _to_hex_state(ark_state),
    })

    plain_block = _state_to_bytes(ark_state)

    # sembunyikan padding untuk tampilan plaintext
    try:
        from .key_utils import unpad_pkcs7
        show_plain_text = unpad_pkcs7(plain_block).decode("utf-8", errors="ignore")
    except:
        show_plain_text = plain_block.decode("utf-8", errors="ignore")

    result["plaintext_block_hex"] = _to_hex_bytes(plain_block)
    result["plaintext_readable"] = show_plain_text
    return result

import base64

def _hex_bytes_to_base64(hex_str: str) -> str:
    """Mengubah string hex 'AA BB CC' menjadi Base64."""
    try:
        b = bytes(int(h, 16) for h in hex_str.split())
        return base64.b64encode(b).decode()
    except:
        return "(invalid data)"

