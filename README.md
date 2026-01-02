# mojo-jwt

A pure Mojo implementation of JSON Web Token (JWT) validation with HS256 support.

## Features

- **Base64URL Encoding/Decoding** - RFC 4648 compliant URL-safe Base64
- **SHA-256 Hash** - Pure Mojo implementation
- **HMAC-SHA256** - RFC 2104 compliant message authentication
- **HS256 Algorithm** - HMAC-SHA256 signing and verification
- **JWT Parsing** - Parse and validate JWT structure
- **Claims Validation** - Standard claims (exp, nbf, iat, iss, aud, sub, jti)
- **Constant-time Comparison** - Protection against timing attacks

## Installation

Add to your `pixi.toml`:

```toml
[dependencies]
mojo-jwt = { path = "../mojo-jwt" }
```

## Quick Start

### Validate a JWT Token

```mojo
from mojo_jwt import validate_hs256, ValidationOptions, validate

fn main():
    var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    var secret = "your-secret-key"
    var current_time: Int64 = 1703721600  # Unix timestamp

    # Simple validation
    var result = validate_hs256(token, secret, current_time)
    if result.is_ok():
        var validated = result.value()
        print("Token is valid!")
        print("Subject:", validated.claims().sub)
    else:
        print("Validation failed:", str(result.error()))
```

### Advanced Validation with Options

```mojo
from mojo_jwt import validate, ValidationOptions

fn validate_with_requirements():
    var token = "..."
    var options = ValidationOptions("your-secret")
    options = options
        .with_current_time(1703721600)
        .with_clock_skew(60)  # Allow 60 seconds clock drift
        .require_issuer("my-auth-service")
        .require_audience("my-api")

    var result = validate(token, options)
    if result.is_ok():
        print("Token validated successfully!")
```

### Create a JWT Token

```mojo
from mojo_jwt import create_jwt, JWTHeader

fn create_token():
    var header = JWTHeader("HS256", "JWT")
    var claims = '{"sub":"user123","iss":"my-service","exp":1703725200}'
    var secret = "my-secret-key"

    var token = create_jwt(header, claims, secret)
    print("Token:", token)
```

### Parse Without Verification (Debugging)

```mojo
from mojo_jwt import parse_jwt, decode_without_verification

fn inspect_token():
    var token = "..."
    var result = parse_jwt(token)
    if result.is_ok():
        var jwt = result.value()
        print("Algorithm:", jwt.header.alg)
        print("Subject:", jwt.claims.sub)
        print("Expires:", jwt.claims.exp)
```

## API Reference

### Validation Functions

| Function | Description |
|----------|-------------|
| `validate(token, options)` | Full validation with all options |
| `validate_hs256(token, secret, time)` | Quick HS256 validation |
| `decode_without_verification(token)` | Parse without signature check |
| `is_expired(token, time)` | Quick expiration check |
| `get_claims(token)` | Extract claims without verification |
| `get_algorithm(token)` | Get algorithm from header |

### ValidationOptions

```mojo
var options = ValidationOptions(secret)
options = options
    .with_current_time(timestamp)      # Set current time for exp/nbf checks
    .with_clock_skew(seconds)          # Allow clock drift
    .require_issuer(iss)               # Require specific issuer
    .require_audience(aud)             # Require specific audience
    .skip_exp_validation()             # Don't check expiration
    .skip_nbf_validation()             # Don't check not-before
    .allow_none()                      # Allow 'none' algorithm (DANGEROUS)
```

### Claims Structure

```mojo
@value
struct Claims:
    var iss: String    # Issuer
    var sub: String    # Subject
    var aud: String    # Audience
    var exp: Int64     # Expiration time (Unix timestamp)
    var nbf: Int64     # Not before (Unix timestamp)
    var iat: Int64     # Issued at (Unix timestamp)
    var jti: String    # JWT ID
```

### Error Types

| Error | Description |
|-------|-------------|
| `INVALID_FORMAT` | JWT doesn't have three parts |
| `INVALID_BASE64` | Base64URL decoding failed |
| `INVALID_HEADER` | Header JSON is malformed |
| `INVALID_PAYLOAD` | Payload JSON is malformed |
| `INVALID_SIGNATURE` | Signature verification failed |
| `UNSUPPORTED_ALGORITHM` | Algorithm not supported |
| `TOKEN_EXPIRED` | Token exp claim is in the past |
| `TOKEN_NOT_YET_VALID` | Token nbf claim is in the future |
| `INVALID_ISSUER` | Issuer doesn't match expected |
| `INVALID_AUDIENCE` | Audience doesn't match expected |
| `MISSING_CLAIM` | Required claim is missing |

## Low-Level API

### Base64URL

```mojo
from mojo_jwt import base64url_encode, base64url_decode, base64url_encode_string

var encoded = base64url_encode_string("Hello, World!")
var decoded = base64url_decode_to_string(encoded)
```

### SHA-256

```mojo
from mojo_jwt import sha256, sha256_string, sha256_hex, bytes_to_hex

var hash = sha256_string("Hello")
var hex = bytes_to_hex(hash)
```

### HMAC-SHA256

```mojo
from mojo_jwt import hmac_sha256_string

var mac = hmac_sha256_string("key", "message")
```

### HS256 Signing

```mojo
from mojo_jwt import hs256_sign, hs256_verify

var signature = hs256_sign(secret, "header.payload")
var is_valid = hs256_verify(secret, "header.payload", signature)
```

## Security Considerations

1. **Never use `none` algorithm in production** - It provides no security
2. **Use strong secrets** - At least 256 bits of entropy for HS256
3. **Always validate claims** - Check exp, iss, aud as appropriate
4. **Clock skew** - Allow reasonable clock drift (60-300 seconds)
5. **Constant-time comparison** - This library uses constant-time signature comparison

## Dependencies

- No external dependencies
- Pure Mojo implementation
- Note: Uses placeholder import for `mojo-json` (for future JSON parsing)

## Testing

```bash
# Run tests
magic run mojo tests/test_jwt.mojo
```

## RFC Compliance

- RFC 7519 - JSON Web Token (JWT)
- RFC 7518 - JSON Web Algorithms (JWA) - HS256 only
- RFC 4648 - Base16, Base32, Base64 Data Encodings
- RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
- FIPS 180-4 - Secure Hash Standard (SHA-256)

## License

MIT License

## Part of mojo-contrib

This library is part of [mojo-contrib](https://github.com/atsentia/mojo-contrib), a collection of pure Mojo libraries.
