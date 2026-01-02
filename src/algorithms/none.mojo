"""'none' algorithm for JWT - NO SIGNATURE.

WARNING: This algorithm provides NO security and should ONLY be used for testing.
Tokens with alg=none can be forged by anyone.

Use of this algorithm in production is a critical security vulnerability.
"""

from ..error import JWTError, JWTResult


@value
struct NoneAlgorithm:
    """'none' algorithm - no signature verification.

    WARNING: This provides no security. For testing only.
    """

    fn __init__(out self):
        """Initialize the none algorithm."""
        pass

    fn sign(self, message: String) -> List[UInt8]:
        """'Sign' a message (returns empty signature).

        Args:
            message: The message (ignored).

        Returns:
            Empty byte list.
        """
        return List[UInt8]()

    fn sign_base64url(self, message: String) -> String:
        """'Sign' a message and return Base64URL signature.

        Args:
            message: The message (ignored).

        Returns:
            Empty string (no signature).
        """
        return ""

    fn verify(self, message: String, signature: List[UInt8]) -> Bool:
        """Verify a signature (always accepts empty signature).

        Args:
            message: The message (ignored).
            signature: Must be empty for none algorithm.

        Returns:
            True if signature is empty.
        """
        return len(signature) == 0

    fn verify_base64url(self, message: String, signature_b64: String) -> Bool:
        """Verify a Base64URL signature (must be empty).

        Args:
            message: The message (ignored).
            signature_b64: Must be empty for none algorithm.

        Returns:
            True if signature is empty.
        """
        return len(signature_b64) == 0

    @staticmethod
    fn algorithm_name() -> String:
        """Get the algorithm name for JWT header."""
        return "none"


fn none_sign(message: String) -> String:
    """'Sign' a message with none algorithm (returns empty).

    Args:
        message: The message (ignored).

    Returns:
        Empty string.
    """
    var alg = NoneAlgorithm()
    return alg.sign_base64url(message)


fn none_verify(message: String, signature: String) -> Bool:
    """Verify a none algorithm signature (must be empty).

    Args:
        message: The message (ignored).
        signature: Must be empty.

    Returns:
        True if signature is empty.
    """
    var alg = NoneAlgorithm()
    return alg.verify_base64url(message, signature)


fn create_unsigned_jwt_signature() -> String:
    """Create an unsigned JWT signature (empty string).

    Returns:
        Empty string for none algorithm.
    """
    return ""
