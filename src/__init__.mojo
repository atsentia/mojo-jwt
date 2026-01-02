"""mojo-jwt: Pure Mojo JWT validation library.

A complete JWT (JSON Web Token) implementation in pure Mojo with HS256 support.

Features:
- Base64URL encoding/decoding (RFC 4648)
- JWT parsing and validation (RFC 7519)
- HS256 (HMAC-SHA256) signature verification
- Standard claims validation (exp, nbf, iat, iss, aud)
- Constant-time signature comparison (timing attack protection)

Example usage:

```mojo
from mojo_jwt import validate_hs256, ValidationOptions, validate

# Simple validation with HS256
fn main():
    var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    var secret = "your-secret-key"
    var current_time: Int64 = 1703721600  # Unix timestamp

    var result = validate_hs256(token, secret, current_time)
    if result.is_ok():
        var validated = result.value()
        print("Token is valid!")
        print("Subject:", validated.claims().sub)
    else:
        print("Validation failed:", str(result.error()))
```

For full validation options:

```mojo
from mojo_jwt import validate, ValidationOptions

fn validate_with_options():
    var options = ValidationOptions("secret")
    options = options
        .with_current_time(1703721600)
        .with_clock_skew(60)
        .require_issuer("my-service")
        .require_audience("my-api")

    var result = validate(token, options)
```
"""

# Error types
from .error import JWTError, JWTErrorKind, JWTResult

# Base64URL encoding
from .base64url import (
    base64url_encode,
    base64url_encode_string,
    base64url_decode,
    base64url_decode_to_string,
    bytes_equal,
)

# Algorithms
from .algorithms import (
    Algorithm,
    SHA256,
    sha256,
    sha256_string,
    sha256_hex,
    bytes_to_hex,
    hmac_sha256,
    hmac_sha256_string,
    HS256Algorithm,
    hs256_sign,
    hs256_verify,
    NoneAlgorithm,
)

# Claims
from .claims import (
    Claims,
    ClaimsValidationOptions,
    validate_claims,
    is_expired,
    is_not_yet_valid,
)

# Token structure
from .token import (
    JWT,
    JWTHeader,
    parse_jwt,
    create_jwt,
)

# Validation
from .validator import (
    ValidationOptions,
    ValidatedToken,
    validate,
    validate_hs256,
    verify_signature,
    decode_without_verification,
    get_claims,
    get_algorithm,
)
