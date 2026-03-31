import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

KEYS_DIR = "keys"
KEY_PASSWORD = b"securepo_demo_key_password"


def load_private_key(username):
    path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=KEY_PASSWORD
        )


def load_public_key(username):
    path = os.path.join(KEYS_DIR, f"{username}_public.pem")
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_po_hash(username, po_hash):
    private_key = load_private_key(username)

    signature = private_key.sign(
        po_hash.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("utf-8")


def verify_po_signature(username, po_hash, signature_b64):
    public_key = load_public_key(username)
    signature = base64.b64decode(signature_b64.encode("utf-8"))

    try:
        public_key.verify(
            signature,
            po_hash.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def rsa_encrypt_session_key(recipient_username, session_key_bytes):
    public_key = load_public_key(recipient_username)

    encrypted_key = public_key.encrypt(
        session_key_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_key).decode("utf-8")


def rsa_decrypt_session_key(recipient_username, encrypted_session_key_b64):
    private_key = load_private_key(recipient_username)
    encrypted_key = base64.b64decode(encrypted_session_key_b64.encode("utf-8"))

    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return session_key


def generate_nonce():
    return os.urandom(16)


def sign_nonce(username, nonce):
    private_key = load_private_key(username)

    signature = private_key.sign(
        nonce,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("utf-8")


def verify_nonce(username, nonce, signature_b64):
    public_key = load_public_key(username)
    signature = base64.b64decode(signature_b64.encode("utf-8"))

    try:
        public_key.verify(
            signature,
            nonce,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False