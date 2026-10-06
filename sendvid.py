import os
import time
import matplotlib.pyplot as plt

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt

# =====================================================
# CREATE FOLDERS
# =====================================================

os.makedirs("encrypted", exist_ok=True)

# =====================================================
# LOAD VIDEO
# =====================================================

file_path = "files/vid.mp4"

with open(file_path, "rb") as f:
    video_data = f.read()

print("\nVideo loaded successfully.")

# =====================================================
# AES ENCRYPTION
# =====================================================

print("\nRunning AES Encryption...")

start_aes = time.time()

aes_key = get_random_bytes(16)

cipher_aes = AES.new(aes_key, AES.MODE_EAX)

ciphertext, tag = cipher_aes.encrypt_and_digest(video_data)

aes_time = time.time() - start_aes

with open("encrypted/encrypted_video.bin", "wb") as f:
    f.write(cipher_aes.nonce + tag + ciphertext)

print("AES Encryption Completed.")

# =====================================================
# RSA ENCRYPTION
# =====================================================

print("\nEncrypting AES Key using RSA...")

start_rsa = time.time()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

encrypted_key_rsa = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

rsa_time = time.time() - start_rsa

with open("encrypted/aes_key_rsa.bin", "wb") as f:
    f.write(encrypted_key_rsa)

with open("encrypted/private.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

print("RSA Encryption Completed.")

# =====================================================
# KYBER ENCRYPTION
# =====================================================

print("\nEncrypting AES Key using Kyber...")

start_kyber = time.time()

public_key_pq, private_key_pq = generate_keypair()

ciphertext_pq, shared_secret = encrypt(public_key_pq)

kyber_time = time.time() - start_kyber

with open("encrypted/kyber_cipher.bin", "wb") as f:
    f.write(ciphertext_pq)

with open("encrypted/kyber_private.key", "wb") as f:
    f.write(private_key_pq)

print("Kyber Encryption Completed.")

# =====================================================
# PERFORMANCE
# =====================================================

print("\n========== PERFORMANCE ==========")

print(f"AES Encryption Time   : {aes_time:.6f} sec")
print(f"RSA Encryption Time   : {rsa_time:.6f} sec")
print(f"Kyber Encryption Time : {kyber_time:.6f} sec")

print("\nKyber Faster Than RSA By {:.6f} Seconds".format(
    rsa_time - kyber_time
))

# =====================================================
# TLS HANDSHAKE TEST
# =====================================================

print("\n========== TLS HANDSHAKES ==========")

rsa_handshakes = 0

rsa_private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

rsa_public = rsa_private.public_key()

start = time.time()

while time.time() - start < 10:

    rsa_public.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    rsa_handshakes += 1

pq_public, pq_private = generate_keypair()

kyber_handshakes = 0

start = time.time()

while time.time() - start < 10:

    encrypt(pq_public)

    kyber_handshakes += 1

print(f"RSA Handshakes   : {rsa_handshakes}")
print(f"Kyber Handshakes : {kyber_handshakes}")

# =====================================================
# GRAPH 1
# =====================================================

plt.figure(figsize=(6,5))

plt.bar(
    ["RSA","Kyber"],
    [rsa_time,kyber_time]
)

plt.title("Encryption Time Comparison")
plt.ylabel("Time (sec)")

plt.savefig("encryption_comparison.png")
plt.show()

# =====================================================
# GRAPH 2
# =====================================================

plt.figure(figsize=(6,5))

plt.bar(
    ["RSA","Kyber"],
    [rsa_handshakes,kyber_handshakes]
)

plt.title("TLS Handshakes in 10 Seconds")
plt.ylabel("Connections")

plt.savefig("tls_handshake_performance.png")
plt.show()