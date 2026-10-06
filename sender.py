import hashlib
from PIL import Image
import os
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from pqcrypto.kem.ml_kem_512 import generate_keypair, encrypt

# Create folders
os.makedirs("encrypted", exist_ok=True)


# LOAD IMAGE


file_path = "files/mansae.jpg"


with open(file_path, "rb") as f:
    image_data = f.read()

print("\nImage loaded successfully.")


# AES ENCRYPTION


print("\nRunning AES Encryption...")

start_aes = time.time()

aes_key = get_random_bytes(16)

cipher_aes = AES.new(aes_key, AES.MODE_EAX)

ciphertext, tag = cipher_aes.encrypt_and_digest(image_data)

aes_time = time.time() - start_aes

with open("encrypted/encrypted_image.bin", "wb") as f:
    f.write(cipher_aes.nonce + tag + ciphertext)

print("AES Encryption Completed.")


# RSA ENCRYPTION


print("\nEncrypting AES key using RSA...")

start_rsa = time.time()

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

encrypted_key_rsa = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
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


# KYBER ENCRYPTION


print("\nEncrypting AES key using Kyber...")

start_kyber = time.time()

public_key_pq, private_key_pq = generate_keypair()

ciphertext_pq, shared_secret = encrypt(public_key_pq)

kyber_time = time.time() - start_kyber

with open("encrypted/kyber_cipher.bin", "wb") as f:
    f.write(ciphertext_pq)

with open("encrypted/kyber_private.key", "wb") as f:
    f.write(private_key_pq)

print("Kyber Encryption Completed.")


# RESULTS


print("\n========== PERFORMANCE ==========")

print(f"AES Encryption Time: {aes_time:.6f} sec")
print(f"RSA Encryption Time: {rsa_time:.6f} sec")
print(f"Kyber Encryption Time: {kyber_time:.6f} sec")

print("\nEncryption completed successfully.")
print("\n Kyber Encrypted faster than RSA by {:.6f} seconds.".format(rsa_time-kyber_time))


# TLS HANDSHAKE PERFORMANCE SIMULATION


print("\n========== TLS HANDSHAKE PERFORMANCE ==========")

# Simulate RSA TLS Handshakes
rsa_handshakes = 0

start = time.time()

while time.time() - start < 10:
    
    # RSA key generation
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    # Encrypt AES key
    public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    rsa_handshakes += 1

# Simulate Kyber TLS Handshakes
kyber_handshakes = 0

start = time.time()

while time.time() - start < 10:

    public_key_pq, private_key_pq = generate_keypair()

    encrypt(public_key_pq)

    kyber_handshakes += 1

# Results

print(f"\nRSA TLS Handshakes in 10 sec : {rsa_handshakes}")

print(f"Kyber TLS Handshakes in 10 sec : {kyber_handshakes}")

if kyber_handshakes > rsa_handshakes:
    print("\nKyber established more secure connections than RSA.")
else:
    print("\nRSA established more secure connections than Kyber.")

import matplotlib.pyplot as plt


# Data
algorithms = ['RSA', 'Kyber']

encryption_times = [rsa_time, kyber_time]

handshakes = [rsa_handshakes, kyber_handshakes]

# =====================================================
# GRAPH 1 — Encryption Time
# =====================================================

plt.figure(figsize=(6,5))

plt.bar(algorithms, encryption_times)

plt.title("Encryption Time Comparison")

plt.xlabel("Algorithms")

plt.ylabel("Time (seconds)")

plt.savefig("encryption_comparison.png")

plt.show()

# =====================================================
# GRAPH 2 — TLS Handshake Performance
# =====================================================

plt.figure(figsize=(6,5))

plt.bar(algorithms, handshakes)

plt.title("TLS Handshakes in 10 Seconds")

plt.xlabel("Algorithms")

plt.ylabel("Number of Handshakes")

plt.savefig("tls_handshake_performance.png")

plt.show()