"""
CSA5109 - EHR Cryptographic Integrity and Digital Signature Demonstration
Python 3.12
Synthetic data only; no real patient information is used.
"""
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

RECORD = """Patient ID: EHR-001
Visit Date: 2026-08-28
Department: Cardiology
Diagnosis: Hypertension
Prescription: Amlodipine 5 mg once daily
Provider: Dr. A. Kumar
"""

def hash_record(record, algorithm="sha256"):
    return hashlib.new(algorithm, record.encode("utf-8")).hexdigest()

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    return private_key, private_key.public_key()

def sign_record(record, private_key):
    return private_key.sign(
        record.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(record, signature, public_key):
    try:
        public_key.verify(
            signature,
            record.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def main():
    private_key, public_key = generate_keys()

    print("=== EHR Integrity and Digital Signature Demo ===")
    print("SHA-256:", hash_record(RECORD, "sha256"))
    print("SHA-3-256:", hash_record(RECORD, "sha3_256"))

    signature = sign_record(RECORD, private_key)
    print("Signature size:", len(signature), "bytes")
    print("Original verification:", verify_signature(RECORD, signature, public_key))

    tampered = RECORD.replace("Hypertension", "Hypotension")
    print("Tampered verification:", verify_signature(tampered, signature, public_key))

if __name__ == "__main__":
    main()
