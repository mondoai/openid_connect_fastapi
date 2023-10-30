"""
TODO
"""
import base64
import hashlib
import hmac

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from oidc_config import OIDCConfig


class CryptoUtils:
    """TODO"""

    oidc_config = None
    key_length = 32

    @classmethod
    async def init_module(
        cls,
        oidc_config: OIDCConfig,
    ):
        """TODO"""
        CryptoUtils.oidc_config = oidc_config

    @classmethod
    async def get_sha256_digest(cls, clear_text: str):
        """TODO"""
        return hashlib.sha256(clear_text.encode("utf8")).hexdigest()

    @classmethod
    async def _get_encoded_key(cls, key_text):
        """TODO"""
        assert CryptoUtils.oidc_config is not None

        key_hash = await CryptoUtils.get_sha256_digest(key_text)
        return base64.b64decode(key_hash.encode("utf8"))[: CryptoUtils.key_length]

    @classmethod
    async def get_encryption_key(cls):
        """TODO"""
        encryption_key = (
            CryptoUtils.oidc_config.module_config.configuration.vault_keeper.encryption_key
        )
        return await CryptoUtils._get_encoded_key(encryption_key)

    @classmethod
    async def get_hmac_key(cls):
        """TODO"""
        hmac_key = (
            CryptoUtils.oidc_config.module_config.configuration.vault_keeper.hmac_key
        )
        return await CryptoUtils._get_encoded_key(hmac_key)

    @classmethod
    async def encrypt_password(
        cls,
        password: str,
    ) -> str:
        """TODO"""

        encryption_key = await CryptoUtils.get_encryption_key()

        raw_bytes = pad(password.encode("utf8"), 16)
        cipher = AES.new(encryption_key, AES.MODE_ECB)

        encrypted_password_bytes = cipher.encrypt(raw_bytes)

        hmac_key = await CryptoUtils.get_hmac_key()
        encrypted_password_bytes = hmac.digest(hmac_key, encrypted_password_bytes, digest="sha256")

        return base64.b64encode(encrypted_password_bytes).decode("utf8")

    @classmethod
    async def encrypt_text(cls, plain_text: str) -> str:
        """TODO"""
        encryption_key = await CryptoUtils.get_encryption_key()
        raw_bytes = pad(plain_text.encode("utf8"), 16)
        cipher = AES.new(encryption_key, AES.MODE_ECB)

        encrypted_text_bytes = cipher.encrypt(raw_bytes)

        return encrypted_text_bytes.hex()

    @classmethod
    async def decrypt_text(cls, cipher_text: str) -> str:
        """TODO"""
        cipher_bytes = bytes.fromhex(cipher_text)
        encryption_key = await CryptoUtils.get_encryption_key()
        cipher = AES.new(encryption_key, AES.MODE_ECB)

        plain_text_bytes = cipher.decrypt(cipher_bytes)

        return unpad(plain_text_bytes, 16).decode("utf8")
