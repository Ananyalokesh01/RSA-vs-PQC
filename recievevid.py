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

print("\nDecrypting AES Key Using RSA...")

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
# VIDEO DECRYPTION
# =====================================================

print("\nDecrypting Video...")

with open("encrypted/encrypted_video.bin", "rb") as f:
    file_data = f.read()

nonce = file_data[:16]
tag = file_data[16:32]
ciphertext = file_data[32:]

cipher_aes = AES.new(
    aes_key,
    AES.MODE_EAX,
    nonce=nonce
)

decrypted_video = cipher_aes.decrypt_and_verify(
    ciphertext,
    tag
)

with open("decrypted/decrypted_video.mp4", "wb") as f:
    f.write(decrypted_video)

print("Video Decryption Completed.")

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

original_file = "files/vid.mp4"
received_file = "decrypted/decrypted_video.mp4"

original_size = os.path.getsize(original_file)
received_size = os.path.getsize(received_file)

print("\n========== FILE SIZE ==========")

print("Original :", original_size)
print("Received :", received_size)

# =====================================================
# HASH COMPARISON
# =====================================================

def get_hash(file):

    with open(file, "rb") as f:
        return hashlib.sha256(
            f.read()
        ).hexdigest()

original_hash = get_hash(original_file)
received_hash = get_hash(received_file)

print("\n========== SHA256 ==========")

print("Original :", original_hash)
print("Received :", received_hash)


# =====================================================
# FINAL RESULT
# =====================================================

if (
    original_size == received_size and
    original_hash == received_hash
):

    print("\n VIDEO VERIFIED SUCCESSFULLY")
    print(" NO DATA LOSS")
    print(" FILE INTEGRITY PRESERVED")

else:

    print("\n VIDEO VERIFICATION FAILED")