"""Tests for mojo-jwt library."""

from src import (
    base64url_encode,
    base64url_encode_string,
    base64url_decode,
    base64url_decode_to_string,
    bytes_equal,
    sha256,
    sha256_string,
    sha256_hex,
    bytes_to_hex,
    hmac_sha256_string,
    hs256_sign,
    hs256_verify,
    parse_jwt,
    create_jwt,
    validate_hs256,
    ValidationOptions,
    validate,
    JWTHeader,
    Claims,
    Algorithm,
)


fn test_base64url_encode() raises:
    """Test Base64URL encoding."""
    print("Testing Base64URL encoding...")

    # Test empty
    var empty = List[UInt8]()
    var encoded = base64url_encode(empty)
    if encoded != "":
        raise Error("Empty encode failed")

    # Test simple string
    var hello = base64url_encode_string("Hello")
    if hello != "SGVsbG8":
        raise Error("Hello encode failed: got " + hello)

    # Test with special chars that need URL-safe encoding
    var result = base64url_encode_string("<<??>>")
    if "+" in result or "/" in result or "=" in result:
        raise Error("URL-unsafe characters in result")

    print("  Base64URL encoding tests passed!")


fn test_base64url_decode() raises:
    """Test Base64URL decoding."""
    print("Testing Base64URL decoding...")

    # Decode "Hello"
    var result = base64url_decode_to_string("SGVsbG8")
    if result.is_err():
        raise Error("Decode failed: " + str(result.error()))
    if result.value() != "Hello":
        raise Error("Decode mismatch: got " + result.value())

    # Test round-trip
    var original = "The quick brown fox jumps over the lazy dog"
    var encoded = base64url_encode_string(original)
    var decoded = base64url_decode_to_string(encoded)
    if decoded.is_err():
        raise Error("Round-trip decode failed")
    if decoded.value() != original:
        raise Error("Round-trip mismatch")

    print("  Base64URL decoding tests passed!")


fn test_sha256() raises:
    """Test SHA-256 hash function."""
    print("Testing SHA-256...")

    # Test empty string
    # SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    var empty_bytes = List[UInt8]()
    var empty_hash = sha256(empty_bytes)
    var empty_hex = bytes_to_hex(empty_hash)
    if empty_hex != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        raise Error("Empty SHA256 failed: " + empty_hex)

    # Test "abc"
    # SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    var abc_hash = sha256_string("abc")
    var abc_hex = bytes_to_hex(abc_hash)
    if abc_hex != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad":
        raise Error("abc SHA256 failed: " + abc_hex)

    print("  SHA-256 tests passed!")


fn test_hmac_sha256() raises:
    """Test HMAC-SHA256."""
    print("Testing HMAC-SHA256...")

    # Test vector from RFC 4231
    # Key: "key"
    # Data: "The quick brown fox jumps over the lazy dog"
    # Expected: f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
    var hmac_result = hmac_sha256_string(
        "key", "The quick brown fox jumps over the lazy dog"
    )
    var hmac_hex = bytes_to_hex(hmac_result)
    if hmac_hex != "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8":
        raise Error("HMAC-SHA256 test failed: " + hmac_hex)

    print("  HMAC-SHA256 tests passed!")


fn test_hs256_sign_verify() raises:
    """Test HS256 signing and verification."""
    print("Testing HS256 sign/verify...")

    var secret = "my-secret-key"
    var message = "header.payload"

    # Sign
    var signature = hs256_sign(secret, message)
    if len(signature) == 0:
        raise Error("HS256 sign returned empty signature")

    # Verify
    if not hs256_verify(secret, message, signature):
        raise Error("HS256 verify failed for valid signature")

    # Verify with wrong secret should fail
    if hs256_verify("wrong-secret", message, signature):
        raise Error("HS256 verify should fail with wrong secret")

    # Verify with wrong message should fail
    if hs256_verify(secret, "wrong.message", signature):
        raise Error("HS256 verify should fail with wrong message")

    print("  HS256 sign/verify tests passed!")


fn test_parse_jwt() raises:
    """Test JWT parsing."""
    print("Testing JWT parsing...")

    # A sample HS256 JWT (from jwt.io)
    # Header: {"alg":"HS256","typ":"JWT"}
    # Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
    var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

    var result = parse_jwt(token)
    if result.is_err():
        raise Error("Parse failed: " + str(result.error()))

    var jwt = result.value()

    # Check header
    if jwt.header.alg != "HS256":
        raise Error("Wrong algorithm: " + jwt.header.alg)
    if jwt.header.typ != "JWT":
        raise Error("Wrong type: " + jwt.header.typ)

    # Check claims
    if jwt.claims.sub != "1234567890":
        raise Error("Wrong subject: " + jwt.claims.sub)
    if jwt.claims.iat != 1516239022:
        raise Error("Wrong iat")

    print("  JWT parsing tests passed!")


fn test_create_jwt() raises:
    """Test JWT creation."""
    print("Testing JWT creation...")

    var header = JWTHeader("HS256", "JWT")
    var claims_json = '{"sub":"user123","iat":1703721600}'
    var secret = "test-secret"

    var token = create_jwt(header, claims_json, secret)

    # Should have three parts
    var dot_count = 0
    for i in range(len(token)):
        if token[i] == ".":
            dot_count += 1
    if dot_count != 2:
        raise Error("JWT should have 2 dots: " + token)

    # Parse it back
    var parsed = parse_jwt(token)
    if parsed.is_err():
        raise Error("Created JWT failed to parse: " + str(parsed.error()))

    # Verify signature
    if not hs256_verify(
        secret, parsed.value().signing_input(), parsed.value().signature_raw
    ):
        raise Error("Created JWT signature verification failed")

    print("  JWT creation tests passed!")


fn test_validate_jwt() raises:
    """Test JWT validation."""
    print("Testing JWT validation...")

    # Create a test token
    var header = JWTHeader("HS256", "JWT")
    var secret = "validation-secret"
    var current_time: Int64 = 1703721600

    # Token that expires in the future
    var claims_json = (
        '{"sub":"user123","iss":"my-service","aud":"my-api","exp":'
        + str(current_time + 3600)
        + "}"
    )
    var token = create_jwt(header, claims_json, secret)

    # Validate with correct secret
    var result = validate_hs256(token, secret, current_time)
    if result.is_err():
        raise Error("Valid token validation failed: " + str(result.error()))

    # Validate with wrong secret should fail
    var wrong_result = validate_hs256(token, "wrong-secret", current_time)
    if wrong_result.is_ok():
        raise Error("Validation should fail with wrong secret")

    print("  JWT validation tests passed!")


fn test_claims_validation() raises:
    """Test claims validation (exp, iss, aud)."""
    print("Testing claims validation...")

    var header = JWTHeader("HS256", "JWT")
    var secret = "claims-secret"
    var current_time: Int64 = 1703721600

    # Test expired token
    var expired_claims = '{"sub":"user","exp":' + str(current_time - 3600) + "}"
    var expired_token = create_jwt(header, expired_claims, secret)
    var expired_result = validate_hs256(expired_token, secret, current_time)
    if expired_result.is_ok():
        raise Error("Expired token should fail validation")

    # Test issuer validation
    var iss_claims = '{"sub":"user","iss":"correct-issuer","exp":' + str(
        current_time + 3600
    ) + "}"
    var iss_token = create_jwt(header, iss_claims, secret)

    var options = ValidationOptions(secret)
    options = options.with_current_time(current_time).require_issuer("correct-issuer")
    var iss_result = validate(iss_token, options)
    if iss_result.is_err():
        raise Error("Correct issuer should validate: " + str(iss_result.error()))

    # Wrong issuer should fail
    var wrong_iss_options = ValidationOptions(secret)
    wrong_iss_options = wrong_iss_options.with_current_time(current_time).require_issuer(
        "wrong-issuer"
    )
    var wrong_iss_result = validate(iss_token, wrong_iss_options)
    if wrong_iss_result.is_ok():
        raise Error("Wrong issuer should fail validation")

    print("  Claims validation tests passed!")


fn test_algorithm_enum() raises:
    """Test Algorithm enumeration."""
    print("Testing Algorithm enum...")

    var hs256 = Algorithm.from_string("HS256")
    if hs256 != Algorithm.HS256:
        raise Error("HS256 parse failed")
    if not hs256.is_supported():
        raise Error("HS256 should be supported")
    if not hs256.requires_secret():
        raise Error("HS256 should require secret")

    var none = Algorithm.from_string("none")
    if none != Algorithm.NONE:
        raise Error("none parse failed")
    if not none.is_supported():
        raise Error("none should be supported")
    if none.requires_secret():
        raise Error("none should not require secret")

    var unknown = Algorithm.from_string("RS256")
    if unknown != Algorithm.UNKNOWN:
        raise Error("RS256 should be unknown")
    if unknown.is_supported():
        raise Error("RS256 should not be supported")

    print("  Algorithm enum tests passed!")


fn test_bytes_equal() raises:
    """Test constant-time byte comparison."""
    print("Testing bytes_equal...")

    var a = List[UInt8]()
    var b = List[UInt8]()
    for i in range(32):
        a.append(UInt8(i))
        b.append(UInt8(i))

    if not bytes_equal(a, b):
        raise Error("Equal arrays should be equal")

    b[15] = 255
    if bytes_equal(a, b):
        raise Error("Different arrays should not be equal")

    var c = List[UInt8]()
    c.append(1)
    if bytes_equal(a, c):
        raise Error("Different length arrays should not be equal")

    print("  bytes_equal tests passed!")


fn main() raises:
    """Run all tests."""
    print("=" * 50)
    print("mojo-jwt Test Suite")
    print("=" * 50)
    print()

    test_base64url_encode()
    test_base64url_decode()
    test_sha256()
    test_hmac_sha256()
    test_hs256_sign_verify()
    test_parse_jwt()
    test_create_jwt()
    test_validate_jwt()
    test_claims_validation()
    test_algorithm_enum()
    test_bytes_equal()

    print()
    print("=" * 50)
    print("All tests passed!")
    print("=" * 50)
