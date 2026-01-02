"""JWT signing algorithms.

Supported algorithms:
- HS256: HMAC-SHA256 (symmetric key)
- none: No signature (testing only - INSECURE)
"""

from .sha256 import SHA256, sha256, sha256_string, sha256_hex, bytes_to_hex
from .hmac import hmac_sha256, hmac_sha256_string, hmac_sha256_verify
from .hs256 import (
    HS256Algorithm,
    hs256_sign,
    hs256_verify,
    create_jwt_signature,
    verify_jwt_signature,
)
from .none import NoneAlgorithm, none_sign, none_verify, create_unsigned_jwt_signature


@value
struct Algorithm(Stringable):
    """JWT algorithm enumeration."""

    var value: Int

    alias HS256 = Algorithm(0)
    alias NONE = Algorithm(1)
    alias UNKNOWN = Algorithm(-1)

    fn __str__(self) -> String:
        if self.value == 0:
            return "HS256"
        elif self.value == 1:
            return "none"
        else:
            return "unknown"

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn __ne__(self, other: Self) -> Bool:
        return self.value != other.value

    @staticmethod
    fn from_string(s: String) -> Algorithm:
        """Parse algorithm from string.

        Args:
            s: Algorithm name.

        Returns:
            Corresponding Algorithm value.
        """
        if s == "HS256":
            return Algorithm.HS256
        elif s == "none":
            return Algorithm.NONE
        else:
            return Algorithm.UNKNOWN

    fn is_supported(self) -> Bool:
        """Check if this algorithm is supported."""
        return self.value == 0 or self.value == 1

    fn requires_secret(self) -> Bool:
        """Check if this algorithm requires a secret key."""
        return self.value == 0  # HS256 requires secret
