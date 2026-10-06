RSA vs PQC: Secure Cryptographic Protocol

Overview

This project implements and compares traditional RSA-based key exchange with Post-Quantum Cryptography (PQC using Kyber (ML-KEM-512))

The system demonstrates secure encryption and decryption of text, images, and video files using a hybrid encryption approach. It also measures and compares the performance of RSA and Kyber during the key establishment process.

The main goal is to understand how Post-Quantum Cryptography can improve security against future quantum-computing attacks while maintaining practical performance.

---

Objectives

- Implement secure file encryption and decryption.
- Use AES for symmetric data encryption.
- Use RSA for traditional key encapsulation.
- Use Kyber / ML-KEM-512 for post-quantum key encapsulation.
- Compare RSA and Kyber performance.
- Measure encryption/key-exchange time.
- Demonstrate a hybrid cryptographic protocol.
- Analyze the suitability of PQC for future secure communication.

---

System Architecture

The project follows a hybrid encryption approach:

```text
                 Input File
                     │
                     ▼
              ┌─────────────┐
              │ Generate    │
              │ AES Key     │
              └──────┬──────┘
                     │
                     ▼
              ┌─────────────┐
              │ AES-EAX     │
              │ Encryption  │
              └──────┬──────┘
                     │
                     ▼
               Encrypted File
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
     RSA Encryption       Kyber KEM
     (Traditional)        (PQC)
          │                     │
          ▼                     ▼
     Encrypted AES Key    Shared Secret
          │                     │
          └──────────┬──────────┘
                     ▼
              Secure Transfer
                     │
                     ▼
               Decryption
