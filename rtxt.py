import os
import time
import hashlib

from Crypto.Cipher import AES

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

from pqcrypto.kem.ml_kem_512 import decrypt

# =====================================================
# CREATE FOLDER
# =====================================================

os.makedirs("decrypted", exist_ok=True)

# =====================================================
# RSA DECRYPTION
# =====================================================

print("\nDecrypting AES Key using RSA...")

with open("encrypted/private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("encrypted/aes_key_rsa.bin", "rb") as f:
    encrypted_key_rsa = f.read()

start_rsa = time.time()

aes_key = private_key.decrypt(
    encrypted_key_rsa,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_time = time.time() - start_rsa

print("RSA Decryption Completed.")

# =====================================================
# AES TEXT DECRYPTION
# =====================================================

print("\nDecrypting Text File...")

with open("encrypted/encrypted_text.bin", "rb") as f:
    file_data = f.read()

nonce = file_data[:16]
tag = file_data[16:32]
ciphertext = file_data[32:]

cipher_aes = AES.new(
    aes_key,
    AES.MODE_EAX,
    nonce=nonce
)

decrypted_text = cipher_aes.decrypt_and_verify(
    ciphertext,
    tag
)

with open("decrypted/decrypted_text.txt", "wb") as f:
    f.write(decrypted_text)

print("Text File Decryption Completed.")

# =====================================================
# KYBER DECRYPTION
# =====================================================

print("\nDecrypting Using Kyber...")

with open("encrypted/kyber_private.key", "rb") as f:
    private_key_pq = f.read()

with open("encrypted/kyber_cipher.bin", "rb") as f:
    ciphertext_pq = f.read()

start_kyber = time.time()

shared_secret = decrypt(
    private_key_pq,
    ciphertext_pq
)

kyber_time = time.time() - start_kyber

print("Kyber Decryption Completed.")

# =====================================================
# PERFORMANCE
# =====================================================

print("\n========== PERFORMANCE ==========")

print(f"RSA Decryption Time   : {rsa_time:.6f} sec")
print(f"Kyber Decryption Time : {kyber_time:.6f} sec")
print("\n Kyber Decrypted faster than RSA by {:.6f} seconds.".format(rsa_time-kyber_time)) 

# =====================================================
# FILE SIZE COMPARISON
# =====================================================

original_file = "files/text.txt"
received_file = "decrypted/decrypted_text.txt"

original_size = os.path.getsize(original_file)
received_size = os.path.getsize(received_file)

print("\n========== FILE SIZE COMPARISON ==========")

print(f"Original File Size : {original_size} bytes")
print(f"Received File Size : {received_size} bytes")

# =====================================================
# SHA256 COMPARISON
# =====================================================

def get_hash(filename):
    with open(filename, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

original_hash = get_hash(original_file)
received_hash = get_hash(received_file)

print("\n========== HASH COMPARISON ==========")

print("Original Hash :", original_hash)
print("Received Hash :", received_hash)

# =====================================================
# TEXT CONTENT COMPARISON
# =====================================================

with open(original_file, "r", encoding="utf-8") as f:
    original_text = f.read()

with open(received_file, "r", encoding="utf-8") as f:
    received_text = f.read()

print("\n========== TEXT CONTENT COMPARISON ==========")

if original_text == received_text:
    print("✓ Text Content Matches")
else:
    print("✗ Text Content Differs")

# =====================================================
# FINAL VERIFICATION
# =====================================================

print("\n========== FINAL VERIFICATION ==========")

if (
    original_size == received_size and
    original_hash == received_hash and
    original_text == received_text
):
    print("✓ Transmission Successful")
    print("✓ Integrity Preserved")
    print("✓ No Data Loss")
    print("✓ Encryption and Decryption Successful")
else:
    print("✗ Verification Failed")