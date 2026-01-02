"""Standard JWT claims as defined in RFC 7519.

Registered Claim Names:
- iss (issuer): Principal that issued the JWT
- sub (subject): Principal that is the subject of the JWT
- aud (audience): Recipients the JWT is intended for
- exp (expiration time): Time after which the JWT must not be accepted
- nbf (not before): Time before which the JWT must not be accepted
- iat (issued at): Time at which the JWT was issued
- jti (JWT ID): Unique identifier for the JWT
"""

from .error import JWTError, JWTErrorKind, JWTResult


@value
struct Claims:
    """JWT claims container.

    Holds both registered (standard) and custom claims.
    """

    # Registered claims
    var iss: String  # Issuer
    var sub: String  # Subject
    var aud: String  # Audience (single value - for simplicity)
    var exp: Int64  # Expiration time (Unix timestamp)
    var nbf: Int64  # Not before (Unix timestamp)
    var iat: Int64  # Issued at (Unix timestamp)
    var jti: String  # JWT ID

    # Flags to track which claims are set
    var has_iss: Bool
    var has_sub: Bool
    var has_aud: Bool
    var has_exp: Bool
    var has_nbf: Bool
    var has_iat: Bool
    var has_jti: Bool

    fn __init__(out self):
        """Create empty claims."""
        self.iss = ""
        self.sub = ""
        self.aud = ""
        self.exp = 0
        self.nbf = 0
        self.iat = 0
        self.jti = ""
        self.has_iss = False
        self.has_sub = False
        self.has_aud = False
        self.has_exp = False
        self.has_nbf = False
        self.has_iat = False
        self.has_jti = False

    fn with_iss(mut self, issuer: String) -> Self:
        """Set the issuer claim."""
        self.iss = issuer
        self.has_iss = True
        return self

    fn with_sub(mut self, subject: String) -> Self:
        """Set the subject claim."""
        self.sub = subject
        self.has_sub = True
        return self

    fn with_aud(mut self, audience: String) -> Self:
        """Set the audience claim."""
        self.aud = audience
        self.has_aud = True
        return self

    fn with_exp(mut self, expiration: Int64) -> Self:
        """Set the expiration time claim (Unix timestamp)."""
        self.exp = expiration
        self.has_exp = True
        return self

    fn with_nbf(mut self, not_before: Int64) -> Self:
        """Set the not before claim (Unix timestamp)."""
        self.nbf = not_before
        self.has_nbf = True
        return self

    fn with_iat(mut self, issued_at: Int64) -> Self:
        """Set the issued at claim (Unix timestamp)."""
        self.iat = issued_at
        self.has_iat = True
        return self

    fn with_jti(mut self, jwt_id: String) -> Self:
        """Set the JWT ID claim."""
        self.jti = jwt_id
        self.has_jti = True
        return self


@value
struct ClaimsValidationOptions:
    """Options for validating JWT claims.

    SECURITY NOTE: By default, tokens WITHOUT an `exp` claim are REJECTED.
    This prevents tokens from being valid indefinitely, which is a major
    security vulnerability. Use `allow_no_expiration_INSECURE()` only if
    you have a very specific use case and understand the risks.
    """

    # Expected values
    var expected_issuer: String
    var expected_audience: String

    # Validation flags
    var validate_exp: Bool
    var validate_nbf: Bool
    var validate_iat: Bool
    var validate_iss: Bool
    var validate_aud: Bool

    # Security flags
    var require_exp_claim: Bool  # Require exp claim to be present (default: True)

    # Time validation
    var current_time: Int64  # Current Unix timestamp for time-based validation
    var clock_skew: Int64  # Allowed clock skew in seconds

    fn __init__(out self):
        """Create default validation options.

        By default:
        - Tokens WITHOUT an `exp` claim are REJECTED for security.
        - Expiration and not-before times are validated.
        """
        self.expected_issuer = ""
        self.expected_audience = ""
        self.validate_exp = True
        self.validate_nbf = True
        self.validate_iat = False  # Optional by default
        self.validate_iss = False  # Optional unless expected_issuer set
        self.validate_aud = False  # Optional unless expected_audience set
        self.require_exp_claim = True  # SECURITY: Reject tokens without exp by default
        self.current_time = 0  # Must be set by caller
        self.clock_skew = 60  # 1 minute default skew

    fn require_issuer(mut self, issuer: String) -> Self:
        """Require a specific issuer."""
        self.expected_issuer = issuer
        self.validate_iss = True
        return self

    fn require_audience(mut self, audience: String) -> Self:
        """Require a specific audience."""
        self.expected_audience = audience
        self.validate_aud = True
        return self

    fn with_current_time(mut self, timestamp: Int64) -> Self:
        """Set the current time for validation."""
        self.current_time = timestamp
        return self

    fn with_clock_skew(mut self, seconds: Int64) -> Self:
        """Set the allowed clock skew in seconds."""
        self.clock_skew = seconds
        return self

    fn skip_exp_validation(mut self) -> Self:
        """Skip expiration time validation.

        NOTE: This only skips validation of the exp value. Tokens without
        an exp claim are STILL rejected by default. Use
        `allow_no_expiration_INSECURE()` to allow tokens without exp claims.
        """
        self.validate_exp = False
        return self

    fn skip_nbf_validation(mut self) -> Self:
        """Skip not-before validation."""
        self.validate_nbf = False
        return self

    fn allow_no_expiration_INSECURE(mut self) -> Self:
        """
        Allow tokens WITHOUT an `exp` claim to be valid.

        SECURITY WARNING: THIS IS EXTREMELY DANGEROUS!

        Enabling this option allows tokens to be valid FOREVER. An attacker
        who obtains such a token has permanent access that cannot be revoked
        through expiration. This creates serious security risks:

        1. Stolen tokens grant permanent unauthorized access
        2. No automatic session timeout protection
        3. Token rotation/revocation becomes impossible without blocklists
        4. Violates security best practices (OWASP, NIST)

        ONLY use this if you have a very specific use case AND:
        - Implement a separate token revocation mechanism (blocklist/allowlist)
        - Have short-lived contexts where tokens are immediately invalidated
        - Are in a testing/development environment with no real user data

        For production systems, ALWAYS require expiration claims.
        """
        self.require_exp_claim = False
        self.validate_exp = False  # Also skip exp validation since there's no exp
        return self


fn validate_claims(
    claims: Claims, options: ClaimsValidationOptions
) -> JWTResult[Bool]:
    """Validate JWT claims against the given options.

    Args:
        claims: The claims to validate.
        options: Validation options.

    Returns:
        Ok(True) if all validations pass, Err otherwise.

    Security:
        By default, tokens WITHOUT an `exp` claim are REJECTED. This is a
        critical security measure to prevent tokens from being valid forever.
    """
    # SECURITY: Reject tokens without exp claim by default
    if options.require_exp_claim and not claims.has_exp:
        return JWTResult[Bool].err(JWTError.missing_claim("exp"))

    # Validate expiration (exp)
    if options.validate_exp and claims.has_exp:
        var exp_with_skew = claims.exp + options.clock_skew
        if options.current_time > exp_with_skew:
            return JWTResult[Bool].err(JWTError.token_expired())

    # Validate not-before (nbf)
    if options.validate_nbf and claims.has_nbf:
        var nbf_with_skew = claims.nbf - options.clock_skew
        if options.current_time < nbf_with_skew:
            return JWTResult[Bool].err(JWTError.token_not_yet_valid())

    # Validate issued-at (iat) - token should not be from the future
    if options.validate_iat and claims.has_iat:
        var iat_with_skew = claims.iat - options.clock_skew
        if options.current_time < iat_with_skew:
            return JWTResult[Bool].err(JWTError.token_not_yet_valid())

    # Validate issuer (iss)
    if options.validate_iss:
        if not claims.has_iss:
            return JWTResult[Bool].err(JWTError.missing_claim("iss"))
        if claims.iss != options.expected_issuer:
            return JWTResult[Bool].err(
                JWTError.invalid_issuer(options.expected_issuer, claims.iss)
            )

    # Validate audience (aud)
    if options.validate_aud:
        if not claims.has_aud:
            return JWTResult[Bool].err(JWTError.missing_claim("aud"))
        if claims.aud != options.expected_audience:
            return JWTResult[Bool].err(
                JWTError.invalid_audience(options.expected_audience, claims.aud)
            )

    return JWTResult[Bool].ok(True)


fn is_expired(claims: Claims, current_time: Int64, skew: Int64 = 0) -> Bool:
    """Check if claims indicate an expired token.

    Args:
        claims: The claims to check.
        current_time: Current Unix timestamp.
        skew: Allowed clock skew in seconds.

    Returns:
        True if token is expired.
    """
    if not claims.has_exp:
        return False  # No expiration set
    return current_time > (claims.exp + skew)


fn is_not_yet_valid(claims: Claims, current_time: Int64, skew: Int64 = 0) -> Bool:
    """Check if claims indicate a not-yet-valid token.

    Args:
        claims: The claims to check.
        current_time: Current Unix timestamp.
        skew: Allowed clock skew in seconds.

    Returns:
        True if token is not yet valid.
    """
    if not claims.has_nbf:
        return False  # No nbf set
    return current_time < (claims.nbf - skew)
