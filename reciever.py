import os
import time
import hashlib
from PIL import Image
from Crypto.Cipher import AES


from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

from pqcrypto.kem.ml_kem_512 import decrypt

# Create folder
os.makedirs("decrypted", exist_ok=True)

# =====================================================
# RSA DECRYPTION
# =====================================================

print("\nDecrypting AES key using RSA...")

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
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_time = time.time() - start_rsa

print("RSA Decryption Completed.")

# =====================================================
# IMAGE DECRYPTION USING AES
# =====================================================

print("\nDecrypting Image...")

with open("encrypted/encrypted_image.bin", "rb") as f:
    file_data = f.read()

nonce = file_data[:16]
tag = file_data[16:32]
ciphertext = file_data[32:]

cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)

decrypted_image = cipher_aes.decrypt_and_verify(ciphertext, tag)

with open("decrypted/decrypted_image.jpeg", "wb") as f:
    f.write(decrypted_image)

print("Image Decryption Completed.")

# =====================================================
# KYBER DECRYPTION
# =====================================================

print("\nDecrypting using Kyber...")

with open("encrypted/kyber_private.key", "rb") as f:
    private_key_pq = f.read()

with open("encrypted/kyber_cipher.bin", "rb") as f:
    ciphertext_pq = f.read()

start_kyber = time.time()

shared_secret = decrypt(private_key_pq, ciphertext_pq)

kyber_time = time.time() - start_kyber

print("Kyber Decryption Completed.")


# RESULTS


print("\n========== PERFORMANCE ==========")

print(f"RSA Decryption Time: {rsa_time:.6f} sec")
print(f"Kyber Decryption Time: {kyber_time:.6f} sec")

print("\nDecrypted image saved successfully.")

print("\n Kyber Decrypted faster than RSA by {:.6f} seconds.".format(rsa_time-kyber_time))  
# =====================================================
# FILE SIZE COMPARISON
# =====================================================

original_file = "files/mansae.jpg"
received_file = "decrypted/decrypted_image.jpeg"

original_size = os.path.getsize(original_file)
received_size = os.path.getsize(received_file)

print("\n========== FILE SIZE COMPARISON ==========")

print(f"Original Image Size : {original_size} bytes")
print(f"Received Image Size : {received_size} bytes")

if original_size == received_size:
    print("✓ File sizes match")
else:
    print("✗ File sizes differ")


# =====================================================
# SHA-256 HASH COMPARISON
# =====================================================

def get_hash(filename):
    with open(filename, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

original_hash = get_hash(original_file)
received_hash = get_hash(received_file)

print("\n========== HASH COMPARISON ==========")

print("Original Hash :", original_hash)
print("Received Hash :", received_hash)

if original_hash == received_hash:
    print("✓ Hash values match")
else:
    print("✗ Hash values differ")


# =====================================================
# PIXEL COMPARISON
# =====================================================

print("\n========== PIXEL COMPARISON ==========")

try:
    original_img = Image.open(original_file)
    received_img = Image.open(received_file)

    if original_img.size != received_img.size:
        print("✗ Image dimensions differ")

    elif list(original_img.getdata()) == list(received_img.getdata()):
        print("✓ Images are pixel-perfect identical")

    else:
        print("✗ Images differ at pixel level")

except Exception as e:
    print("Error comparing images:", e)

# =====================================================
# NPCR COMPARISON
# =====================================================

import numpy as np

print("\n========== NPCR COMPARISON ==========")

try:
    original_img = np.array(Image.open(original_file))
    received_img = np.array(Image.open(received_file))

    if original_img.shape != received_img.shape:
        print("Cannot calculate NPCR (different dimensions)")

    else:
        diff_pixels = np.sum(original_img != received_img)

        total_pixels = original_img.size

        npcr = (diff_pixels / total_pixels) * 100

        print(f"Different Pixel Values : {diff_pixels}")

        print(f"Total Pixel Values     : {total_pixels}")

        print(f"NPCR Value             : {npcr:.6f}%")

except Exception as e:
    print("NPCR Error:", e)


# =====================================================
# FINAL PROJECT STATUS
# =====================================================

print("\n========== FINAL VERIFICATION ==========")

if (
    original_size == received_size and
    original_hash == received_hash
):
    print("Transmission Successful")
    print("Integrity Preserved")
    print("No Data Loss Detected")
    print("Encryption and Decryption Successful")
else:
    print("Verification Failed")