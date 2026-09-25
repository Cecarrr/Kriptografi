import hashlib
from Crypto.Cipher import AES, ChaCha20
from Crypto.Util.Padding import pad, unpad

# --- 1. CAESAR CIPHER (Diseragamkan) ---
def caesar_encrypt_core(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt_core(text, shift):
    return caesar_encrypt_core(text, -shift)

# --- 2. RAIL FENCE CIPHER ---
def fence(lst, numrails):
    fence = [[None] * len(lst) for n in range(numrails)]
    rails = list(range(numrails - 1)) + list(range(numrails - 1, 0, -1))
    for n, x in enumerate(lst):
        fence[rails[n % len(rails)]][n] = x
    return [c for rail in fence for c in rail if c is not None]

def railfence_encrypt_core(text, key):
    if key < 2: return text
    return "".join(fence(text, key))

def railfence_decrypt_core(text, key):
    if key < 2: return text
    rng = range(len(text))
    pos = fence(rng, key)
    return "".join(text[pos.index(n)] for n in rng)

# --- 3. CHACHA20 (Versi PyCryptodome untuk Super Enkripsi) ---
def chacha20_encrypt_core(text, key_32):
    cipher = ChaCha20.new(key=key_32)
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    return (cipher.nonce + ciphertext).hex()

def chacha20_decrypt_core(hex_data, key_32):
    raw_data = bytes.fromhex(hex_data)
    nonce, ciphertext = raw_data[:8], raw_data[8:]
    cipher = ChaCha20.new(key=key_32, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# --- 4. AES-128 ---
def aes_encrypt_core(text, key_16):
    cipher = AES.new(key_16, AES.MODE_CBC)
    pt_padded = pad(text.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(pt_padded)
    return (cipher.iv + ciphertext).hex()

def aes_decrypt_core(hex_data, key_16):
    raw_data = bytes.fromhex(hex_data)
    iv, ciphertext = raw_data[:16], raw_data[16:]
    cipher = AES.new(key_16, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ciphertext)
    return unpad(pt_padded, AES.block_size).decode('utf-8')

# --- KEY DERIVATION UNTUK SUPER ENKRIPSI ---
def derive_keys(master_password):
    k_ca = sum(ord(c) for c in master_password) % 26
    k_rf = max(2, (len(master_password) % 8) + 2) 
    k_ch = hashlib.sha256(master_password.encode('utf-8')).digest()
    k_ae = hashlib.md5(master_password.encode('utf-8')).digest()
    return k_ca, k_rf, k_ch, k_ae