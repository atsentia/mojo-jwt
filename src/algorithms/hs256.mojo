"""HS256 (HMAC-SHA256) algorithm for JWT signing and verification.

This implements the HS256 algorithm as specified in RFC 7518 (JSON Web Algorithms).

SECURITY: For HS256, keys should be at least 256 bits (32 bytes) to match
the security level of the underlying SHA-256 hash. Shorter keys reduce
security below the algorithm's design strength.
"""

from ..base64url import base64url_decode, base64url_encode, bytes_equal
from ..error import JWTError, JWTResult
from .hmac import hmac_sha256


alias MIN_KEY_LENGTH: Int = 32
"""Minimum recommended key length for HS256 (256 bits = 32 bytes)."""


@value
struct HS256Algorithm:
    """HS256 (HMAC-SHA256) signing algorithm."""

    var secret: List[UInt8]

    fn __init__(out self, secret: String):
        """Initialize with a secret key.

        SECURITY WARNING: For HS256, keys should be at least 256 bits (32 bytes).
        Shorter keys reduce security below the algorithm's design strength.
        Consider using `HS256Algorithm.create()` which enforces minimum key length.

        Args:
            secret: The secret key as a string.
        """
        self.secret = List[UInt8]()
        for i in range(len(secret)):
            self.secret.append(ord(secret[i]))

        # Warn about weak keys (but don't reject for backwards compatibility)
        if len(self.secret) < MIN_KEY_LENGTH:
            # In production, consider: raise Error("HS256 key must be >= 32 bytes")
            pass  # Silent for now, but see create() for strict validation

    fn __init__(out self, secret: List[UInt8]):
        """Initialize with a secret key as bytes.

        Args:
            secret: The secret key as bytes.
        """
        self.secret = secret

    @staticmethod
    fn create(secret: String) raises -> HS256Algorithm:
        """Create HS256Algorithm with strict key length validation.

        SECURITY: This method enforces minimum 256-bit (32-byte) key length
        as recommended for HS256 to match the security level of SHA-256.

        Args:
            secret: The secret key as a string (must be >= 32 bytes).

        Returns:
            HS256Algorithm instance.

        Raises:
            Error if key is shorter than 32 bytes.
        """
        if len(secret) < MIN_KEY_LENGTH:
            raise Error(
                "SECURITY: HS256 key must be >= " + String(MIN_KEY_LENGTH) +
                " bytes (256 bits). Got " + String(len(secret)) + " bytes. " +
                "Short keys reduce security below HS256's design strength."
            )
        return HS256Algorithm(secret)

    @staticmethod
    fn create_bytes(secret: List[UInt8]) raises -> HS256Algorithm:
        """Create HS256Algorithm from bytes with strict key length validation.

        Args:
            secret: The secret key as bytes (must be >= 32 bytes).

        Returns:
            HS256Algorithm instance.

        Raises:
            Error if key is shorter than 32 bytes.
        """
        if len(secret) < MIN_KEY_LENGTH:
            raise Error(
                "SECURITY: HS256 key must be >= " + String(MIN_KEY_LENGTH) +
                " bytes (256 bits). Got " + String(len(secret)) + " bytes."
            )
        return HS256Algorithm(secret)

    fn sign(self, message: String) -> List[UInt8]:
        """Sign a message with HMAC-SHA256.

        Args:
            message: The message to sign (typically header.payload).

        Returns:
            32-byte signature.
        """
        var message_bytes = List[UInt8]()
        for i in range(len(message)):
            message_bytes.append(ord(message[i]))
        return hmac_sha256(self.secret, message_bytes)

    fn sign_base64url(self, message: String) -> String:
        """Sign a message and return Base64URL-encoded signature.

        Args:
            message: The message to sign.

        Returns:
            Base64URL-encoded signature.
        """
        var signature = self.sign(message)
        return base64url_encode(signature)

    fn verify(self, message: String, signature: List[UInt8]) -> Bool:
        """Verify a signature.

        Args:
            message: The original message.
            signature: The signature to verify.

        Returns:
            True if signature is valid.
        """
        var expected = self.sign(message)
        return bytes_equal(expected, signature)

    fn verify_base64url(self, message: String, signature_b64: String) -> Bool:
        """Verify a Base64URL-encoded signature.

        Args:
            message: The original message.
            signature_b64: The Base64URL-encoded signature.

        Returns:
            True if signature is valid.
        """
        var sig_result = base64url_decode(signature_b64)
        if sig_result.is_err():
            return False
        return self.verify(message, sig_result.value())

    @staticmethod
    fn algorithm_name() -> String:
        """Get the algorithm name for JWT header."""
        return "HS256"


fn hs256_sign(secret: String, message: String) -> String:
    """Sign a message with HS256 and return Base64URL signature.

    Args:
        secret: The secret key.
        message: The message to sign.

    Returns:
        Base64URL-encoded signature.
    """
    var alg = HS256Algorithm(secret)
    return alg.sign_base64url(message)


fn hs256_verify(secret: String, message: String, signature: String) -> Bool:
    """Verify an HS256 signature.

    Args:
        secret: The secret key.
        message: The original message.
        signature: The Base64URL-encoded signature.

    Returns:
        True if signature is valid.
    """
    var alg = HS256Algorithm(secret)
    return alg.verify_base64url(message, signature)


fn create_jwt_signature(
    secret: String, header_b64: String, payload_b64: String
) -> String:
    """Create a JWT signature for header and payload.

    Args:
        secret: The secret key.
        header_b64: Base64URL-encoded header.
        payload_b64: Base64URL-encoded payload.

    Returns:
        Base64URL-encoded signature.
    """
    var message = header_b64 + "." + payload_b64
    return hs256_sign(secret, message)


fn verify_jwt_signature(
    secret: String, header_b64: String, payload_b64: String, signature_b64: String
) -> Bool:
    """Verify a JWT signature.

    Args:
        secret: The secret key.
        header_b64: Base64URL-encoded header.
        payload_b64: Base64URL-encoded payload.
        signature_b64: Base64URL-encoded signature.

    Returns:
        True if signature is valid.
    """
    var message = header_b64 + "." + payload_b64
    return hs256_verify(secret, message, signature_b64)
