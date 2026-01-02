"""JWT token validation.

This module provides comprehensive JWT validation including:
- Structure validation (three parts, valid Base64URL)
- Header validation (algorithm support)
- Signature verification (HS256 or none)
- Claims validation (exp, nbf, iat, iss, aud)
"""

from .error import JWTError, JWTErrorKind, JWTResult
from .token import JWT, JWTHeader, parse_jwt
from .claims import Claims, ClaimsValidationOptions, validate_claims
from .algorithms import Algorithm, verify_jwt_signature
from .algorithms.hs256 import hs256_verify
from .algorithms.none import none_verify


@value
struct ValidationOptions:
    """Options for JWT validation."""

    var secret: String  # Secret key for HS256
    var allow_none_algorithm: Bool  # Allow 'none' algorithm (DANGEROUS)
    var claims_options: ClaimsValidationOptions  # Claims validation options

    fn __init__(out self, secret: String):
        """Create validation options with a secret.

        Args:
            secret: Secret key for signature verification.
        """
        self.secret = secret
        self.allow_none_algorithm = False
        self.claims_options = ClaimsValidationOptions()

    fn with_current_time(mut self, timestamp: Int64) -> Self:
        """Set the current time for validation."""
        self.claims_options = self.claims_options.with_current_time(timestamp)
        return self

    fn with_clock_skew(mut self, seconds: Int64) -> Self:
        """Set the allowed clock skew in seconds."""
        self.claims_options = self.claims_options.with_clock_skew(seconds)
        return self

    fn require_issuer(mut self, issuer: String) -> Self:
        """Require a specific issuer."""
        self.claims_options = self.claims_options.require_issuer(issuer)
        return self

    fn require_audience(mut self, audience: String) -> Self:
        """Require a specific audience."""
        self.claims_options = self.claims_options.require_audience(audience)
        return self

    fn allow_none_INSECURE_FOR_TESTING_ONLY(mut self) -> Self:
        """
        Allow the 'none' algorithm.

        SECURITY WARNING: This is EXTREMELY DANGEROUS and should NEVER be used
        in production. The 'none' algorithm allows ANY token to be forged
        without a signature, completely bypassing authentication.

        Only use this for:
        - Unit tests with mock tokens
        - Local development debugging

        NEVER use in production, staging, or any environment with real user data.
        """
        self.allow_none_algorithm = True
        return self

    fn skip_exp_validation(mut self) -> Self:
        """Skip expiration time validation."""
        self.claims_options = self.claims_options.skip_exp_validation()
        return self

    fn skip_nbf_validation(mut self) -> Self:
        """Skip not-before validation."""
        self.claims_options = self.claims_options.skip_nbf_validation()
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
        self.claims_options = self.claims_options.allow_no_expiration_INSECURE()
        return self


@value
struct ValidatedToken:
    """A validated JWT token with verified claims."""

    var jwt: JWT
    var validated: Bool

    fn __init__(out self, jwt: JWT):
        self.jwt = jwt
        self.validated = True

    fn claims(self) -> Claims:
        """Get the validated claims."""
        return self.jwt.claims

    fn header(self) -> JWTHeader:
        """Get the token header."""
        return self.jwt.header


fn validate(token: String, options: ValidationOptions) -> JWTResult[ValidatedToken]:
    """Validate a JWT token.

    This performs complete validation:
    1. Parse the token structure
    2. Verify the signature
    3. Validate the claims

    Args:
        token: The JWT string to validate.
        options: Validation options.

    Returns:
        ValidatedToken on success, error otherwise.
    """
    # Step 1: Parse the token
    var parse_result = parse_jwt(token)
    if parse_result.is_err():
        return JWTResult[ValidatedToken].err(parse_result.error())

    var jwt = parse_result.value()

    # Step 2: Check algorithm
    var alg = jwt.header.algorithm()

    if alg == Algorithm.UNKNOWN:
        return JWTResult[ValidatedToken].err(
            JWTError.unsupported_algorithm(jwt.header.alg)
        )

    if alg == Algorithm.NONE and not options.allow_none_algorithm:
        return JWTResult[ValidatedToken].err(
            JWTError.unsupported_algorithm(
                "none (disabled for security - use allow_none() to enable)"
            )
        )

    # Step 3: Verify signature
    var sig_valid = verify_signature(jwt, options.secret, alg)
    if not sig_valid:
        return JWTResult[ValidatedToken].err(JWTError.invalid_signature())

    # Step 4: Validate claims
    var claims_result = validate_claims(jwt.claims, options.claims_options)
    if claims_result.is_err():
        return JWTResult[ValidatedToken].err(claims_result.error())

    return JWTResult[ValidatedToken].ok(ValidatedToken(jwt))


fn verify_signature(jwt: JWT, secret: String, alg: Algorithm) -> Bool:
    """Verify the JWT signature.

    Args:
        jwt: Parsed JWT.
        secret: Secret key.
        alg: Algorithm to use.

    Returns:
        True if signature is valid.
    """
    var signing_input = jwt.signing_input()

    if alg == Algorithm.HS256:
        return hs256_verify(secret, signing_input, jwt.signature_raw)
    elif alg == Algorithm.NONE:
        return none_verify(signing_input, jwt.signature_raw)
    else:
        return False


fn validate_hs256(
    token: String,
    secret: String,
    current_time: Int64 = 0,
) -> JWTResult[ValidatedToken]:
    """Validate an HS256-signed JWT with default options.

    Args:
        token: The JWT string.
        secret: The secret key.
        current_time: Current Unix timestamp (0 to skip time validation).

    Returns:
        ValidatedToken on success, error otherwise.
    """
    var options = ValidationOptions(secret)
    if current_time > 0:
        options = options.with_current_time(current_time)
    else:
        options = options.skip_exp_validation().skip_nbf_validation()

    return validate(token, options)


fn decode_without_verification(token: String) -> JWTResult[JWT]:
    """Decode a JWT without verifying the signature.

    WARNING: This is insecure. Only use for debugging or when you
    need to inspect the token before verification.

    Args:
        token: The JWT string.

    Returns:
        Parsed JWT or error.
    """
    return parse_jwt(token)


fn is_expired(token: String, current_time: Int64) -> Bool:
    """Quick check if a token is expired.

    Args:
        token: The JWT string.
        current_time: Current Unix timestamp.

    Returns:
        True if token is expired or invalid.
    """
    var parse_result = parse_jwt(token)
    if parse_result.is_err():
        return True  # Invalid tokens are considered expired

    var jwt = parse_result.value()
    if not jwt.claims.has_exp:
        return False  # No expiration set

    return current_time > jwt.claims.exp


fn get_claims(token: String) -> JWTResult[Claims]:
    """Extract claims from a token without verification.

    WARNING: These claims are NOT verified. Only use for
    inspection before actual validation.

    Args:
        token: The JWT string.

    Returns:
        Claims or error.
    """
    var parse_result = parse_jwt(token)
    if parse_result.is_err():
        return JWTResult[Claims].err(parse_result.error())

    return JWTResult[Claims].ok(parse_result.value().claims)


fn get_algorithm(token: String) -> JWTResult[Algorithm]:
    """Get the algorithm from a token header.

    Args:
        token: The JWT string.

    Returns:
        Algorithm or error.
    """
    var parse_result = parse_jwt(token)
    if parse_result.is_err():
        return JWTResult[Algorithm].err(parse_result.error())

    return JWTResult[Algorithm].ok(parse_result.value().header.algorithm())
