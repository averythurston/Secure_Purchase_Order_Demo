import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def aes_encrypt_payload(payload_dict):
    """
    Encrypt a JSON payload with AES-GCM.
    Returns:
        session_key_bytes,
        encrypted_package_b64
    """
    session_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(session_key)

    nonce = os.urandom(12)
    plaintext = json.dumps(payload_dict, sort_keys=True).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    package = {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }

    encrypted_package_b64 = base64.b64encode(
        json.dumps(package).encode("utf-8")
    ).decode("utf-8")

    return session_key, encrypted_package_b64


def aes_decrypt_payload(session_key, encrypted_package_b64):
    """
    Decrypt an AES-GCM package.
    Returns the original JSON dict.
    """
    aesgcm = AESGCM(session_key)

    package_json = base64.b64decode(encrypted_package_b64.encode("utf-8")).decode("utf-8")
    package = json.loads(package_json)

    nonce = base64.b64decode(package["nonce"].encode("utf-8"))
    ciphertext = base64.b64decode(package["ciphertext"].encode("utf-8"))

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(plaintext.decode("utf-8"))