"""JWT token structure and parsing.

A JWT consists of three Base64URL-encoded parts separated by dots:
    header.payload.signature

Example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
"""

from .base64url import base64url_decode, base64url_decode_to_string, base64url_encode_string
from .error import JWTError, JWTErrorKind, JWTResult
from .claims import Claims
from .algorithms import Algorithm


@value
struct JWTHeader:
    """JWT header containing algorithm and type information."""

    var alg: String  # Algorithm (e.g., "HS256", "none")
    var typ: String  # Type (typically "JWT")

    fn __init__(out self, alg: String = "HS256", typ: String = "JWT"):
        """Create a JWT header.

        Args:
            alg: Algorithm name.
            typ: Token type.
        """
        self.alg = alg
        self.typ = typ

    fn algorithm(self) -> Algorithm:
        """Get the algorithm enum value."""
        return Algorithm.from_string(self.alg)

    fn to_json(self) -> String:
        """Serialize header to JSON string."""
        return '{"alg":"' + self.alg + '","typ":"' + self.typ + '"}'

    @staticmethod
    fn parse_json(json: String) -> JWTResult[JWTHeader]:
        """Parse header from JSON string.

        This is a simple parser that handles the expected JWT header format.

        Args:
            json: JSON string to parse.

        Returns:
            Parsed header or error.
        """
        # Look for "alg" field
        var alg_start = _find_string_value(json, '"alg"')
        if alg_start < 0:
            return JWTResult[JWTHeader].err(
                JWTError.invalid_header("Missing 'alg' field")
            )

        var alg = _extract_string_value(json, alg_start)

        # Look for "typ" field (optional)
        var typ = "JWT"
        var typ_start = _find_string_value(json, '"typ"')
        if typ_start >= 0:
            typ = _extract_string_value(json, typ_start)

        return JWTResult[JWTHeader].ok(JWTHeader(alg, typ))


@value
struct JWT:
    """Parsed JWT token with raw parts."""

    var header_raw: String  # Base64URL-encoded header
    var payload_raw: String  # Base64URL-encoded payload
    var signature_raw: String  # Base64URL-encoded signature
    var header_json: String  # Decoded header JSON
    var payload_json: String  # Decoded payload JSON
    var header: JWTHeader  # Parsed header
    var claims: Claims  # Parsed claims

    fn __init__(out self):
        """Create an empty JWT."""
        self.header_raw = ""
        self.payload_raw = ""
        self.signature_raw = ""
        self.header_json = ""
        self.payload_json = ""
        self.header = JWTHeader()
        self.claims = Claims()

    fn signing_input(self) -> String:
        """Get the signing input (header.payload) for signature verification."""
        return self.header_raw + "." + self.payload_raw

    fn to_string(self) -> String:
        """Reconstruct the full JWT string."""
        return self.header_raw + "." + self.payload_raw + "." + self.signature_raw


fn parse_jwt(token: String) -> JWTResult[JWT]:
    """Parse a JWT token string into its components.

    Args:
        token: The JWT string (header.payload.signature).

    Returns:
        Parsed JWT or error.
    """
    # Find the two dots separating the parts
    var first_dot = -1
    var second_dot = -1

    for i in range(len(token)):
        if token[i] == ".":
            if first_dot < 0:
                first_dot = i
            else:
                second_dot = i
                break

    if first_dot < 0 or second_dot < 0:
        return JWTResult[JWT].err(
            JWTError.invalid_format("JWT must have three parts separated by dots")
        )

    # Extract the three parts
    var header_raw = token[:first_dot]
    var payload_raw = token[first_dot + 1 : second_dot]
    var signature_raw = token[second_dot + 1 :]

    if len(header_raw) == 0 or len(payload_raw) == 0:
        return JWTResult[JWT].err(
            JWTError.invalid_format("JWT header and payload cannot be empty")
        )

    # Decode header
    var header_result = base64url_decode_to_string(header_raw)
    if header_result.is_err():
        return JWTResult[JWT].err(
            JWTError.invalid_header("Failed to decode header: " + str(header_result.error()))
        )
    var header_json = header_result.value()

    # Parse header JSON
    var header_parse_result = JWTHeader.parse_json(header_json)
    if header_parse_result.is_err():
        return JWTResult[JWT].err(header_parse_result.error())
    var header = header_parse_result.value()

    # Decode payload
    var payload_result = base64url_decode_to_string(payload_raw)
    if payload_result.is_err():
        return JWTResult[JWT].err(
            JWTError.invalid_payload("Failed to decode payload: " + str(payload_result.error()))
        )
    var payload_json = payload_result.value()

    # Parse claims from payload
    var claims = _parse_claims(payload_json)

    # Build the JWT
    var jwt = JWT()
    jwt.header_raw = header_raw
    jwt.payload_raw = payload_raw
    jwt.signature_raw = signature_raw
    jwt.header_json = header_json
    jwt.payload_json = payload_json
    jwt.header = header
    jwt.claims = claims

    return JWTResult[JWT].ok(jwt)


fn create_jwt(header: JWTHeader, claims_json: String, secret: String) -> String:
    """Create a signed JWT token.

    Args:
        header: JWT header.
        claims_json: Claims as JSON string.
        secret: Secret key for signing.

    Returns:
        Signed JWT string.
    """
    from .algorithms.hs256 import hs256_sign

    var header_b64 = base64url_encode_string(header.to_json())
    var payload_b64 = base64url_encode_string(claims_json)
    var signing_input = header_b64 + "." + payload_b64

    var signature_b64: String
    if header.alg == "none":
        signature_b64 = ""
    else:
        signature_b64 = hs256_sign(secret, signing_input)

    return signing_input + "." + signature_b64


# Helper functions for simple JSON parsing
# Note: For production use, replace with mojo-json library

fn _find_string_value(json: String, key: String) -> Int:
    """Find the start index of a string value for a given key.

    Returns the index after the opening quote of the value, or -1 if not found.
    """
    var key_pos = -1

    # Search for the key
    for i in range(len(json) - len(key) + 1):
        var match = True
        for j in range(len(key)):
            if json[i + j] != key[j]:
                match = False
                break
        if match:
            key_pos = i
            break

    if key_pos < 0:
        return -1

    # Find the colon after the key
    var colon_pos = -1
    for i in range(key_pos + len(key), len(json)):
        if json[i] == ":":
            colon_pos = i
            break

    if colon_pos < 0:
        return -1

    # Find the opening quote of the value
    for i in range(colon_pos + 1, len(json)):
        if json[i] == '"':
            return i + 1  # Return position after opening quote
        elif json[i] != " " and json[i] != "\t" and json[i] != "\n":
            # Non-whitespace before quote - might be a number or other type
            break

    return -1


fn _extract_string_value(json: String, start: Int) -> String:
    """Extract a string value starting at the given position (after opening quote)."""
    var result = String()
    var i = start

    while i < len(json):
        var c = json[i]
        if c == '"':
            break  # End of string
        elif c == "\\":
            # Handle escape sequences
            if i + 1 < len(json):
                var next_c = json[i + 1]
                if next_c == '"' or next_c == "\\" or next_c == "/":
                    result += next_c
                elif next_c == "n":
                    result += "\n"
                elif next_c == "t":
                    result += "\t"
                elif next_c == "r":
                    result += "\r"
                else:
                    result += next_c
                i += 2
                continue
        else:
            result += c
        i += 1

    return result


fn _find_number_value(json: String, key: String) -> Int64:
    """Find and parse a numeric value for a given key."""
    var key_pos = -1

    # Search for the key
    for i in range(len(json) - len(key) + 1):
        var match = True
        for j in range(len(key)):
            if json[i + j] != key[j]:
                match = False
                break
        if match:
            key_pos = i
            break

    if key_pos < 0:
        return 0

    # Find the colon after the key
    var colon_pos = -1
    for i in range(key_pos + len(key), len(json)):
        if json[i] == ":":
            colon_pos = i
            break

    if colon_pos < 0:
        return 0

    # Extract the number
    var num_str = String()
    for i in range(colon_pos + 1, len(json)):
        var c = json[i]
        if c == " " or c == "\t" or c == "\n":
            if len(num_str) > 0:
                break
            continue
        elif c >= "0" and c <= "9" or c == "-":
            num_str += c
        else:
            break

    if len(num_str) == 0:
        return 0

    return _parse_int64(num_str)


fn _parse_int64(s: String) -> Int64:
    """Parse a string to Int64."""
    var result: Int64 = 0
    var negative = False
    var start = 0

    if len(s) > 0 and s[0] == "-":
        negative = True
        start = 1

    for i in range(start, len(s)):
        var c = s[i]
        if c >= "0" and c <= "9":
            result = result * 10 + Int64(ord(c) - ord("0"))

    return -result if negative else result


fn _has_key(json: String, key: String) -> Bool:
    """Check if a JSON object has a given key."""
    return _find_string_value(json, key) >= 0 or _find_number_value(json, key) != 0


fn _parse_claims(json: String) -> Claims:
    """Parse claims from JSON payload.

    Args:
        json: JSON string containing claims.

    Returns:
        Parsed Claims struct.
    """
    var claims = Claims()

    # Parse string claims
    var iss_start = _find_string_value(json, '"iss"')
    if iss_start >= 0:
        claims.iss = _extract_string_value(json, iss_start)
        claims.has_iss = True

    var sub_start = _find_string_value(json, '"sub"')
    if sub_start >= 0:
        claims.sub = _extract_string_value(json, sub_start)
        claims.has_sub = True

    var aud_start = _find_string_value(json, '"aud"')
    if aud_start >= 0:
        claims.aud = _extract_string_value(json, aud_start)
        claims.has_aud = True

    var jti_start = _find_string_value(json, '"jti"')
    if jti_start >= 0:
        claims.jti = _extract_string_value(json, jti_start)
        claims.has_jti = True

    # Parse numeric claims
    var exp_val = _find_number_value(json, '"exp"')
    if exp_val != 0 or _has_numeric_key(json, '"exp"'):
        claims.exp = exp_val
        claims.has_exp = True

    var nbf_val = _find_number_value(json, '"nbf"')
    if nbf_val != 0 or _has_numeric_key(json, '"nbf"'):
        claims.nbf = nbf_val
        claims.has_nbf = True

    var iat_val = _find_number_value(json, '"iat"')
    if iat_val != 0 or _has_numeric_key(json, '"iat"'):
        claims.iat = iat_val
        claims.has_iat = True

    return claims


fn _has_numeric_key(json: String, key: String) -> Bool:
    """Check if JSON has a numeric value for a key (including 0)."""
    var key_pos = -1
    for i in range(len(json) - len(key) + 1):
        var match = True
        for j in range(len(key)):
            if json[i + j] != key[j]:
                match = False
                break
        if match:
            key_pos = i
            break

    if key_pos < 0:
        return False

    # Find colon
    for i in range(key_pos + len(key), len(json)):
        if json[i] == ":":
            # Found the key with a colon
            return True
        elif json[i] != " " and json[i] != "\t":
            break

    return False
