import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR = "keys"
USERS = ["purchaser1", "supervisor1", "purchasing1"]

# For demo purposes. You can replace this with an environment variable later.
KEY_PASSWORD = b"securepo_demo_key_password"


def generate_rsa_key_pair(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_key_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    public_key_path = os.path.join(KEYS_DIR, f"{username}_public.pem")

    with open(private_key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(KEY_PASSWORD)
            )
        )

    with open(public_key_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"Generated protected keys for {username}")


if __name__ == "__main__":
    os.makedirs(KEYS_DIR, exist_ok=True)

    for user in USERS:
        generate_rsa_key_pair(user)

    print("All password-protected RSA key pairs generated successfully.")