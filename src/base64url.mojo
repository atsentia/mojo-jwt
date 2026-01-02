"""Base64URL encoding/decoding per RFC 4648.

URL-safe Base64 uses:
- Alphabet: A-Z, a-z, 0-9, -, _ (instead of + and /)
- No padding (= characters are omitted)
"""

from .error import JWTError, JWTResult


# Base64URL alphabet (URL-safe variant)
alias BASE64URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


fn _char_to_index(c: UInt8) -> Int:
    """Convert a Base64URL character to its 6-bit value.
    Returns -1 if the character is invalid."""
    # A-Z: 0-25
    if c >= ord("A") and c <= ord("Z"):
        return int(c - ord("A"))
    # a-z: 26-51
    elif c >= ord("a") and c <= ord("z"):
        return int(c - ord("a") + 26)
    # 0-9: 52-61
    elif c >= ord("0") and c <= ord("9"):
        return int(c - ord("0") + 52)
    # -: 62 (URL-safe replacement for +)
    elif c == ord("-"):
        return 62
    # _: 63 (URL-safe replacement for /)
    elif c == ord("_"):
        return 63
    # Invalid character
    else:
        return -1


fn _index_to_char(index: Int) -> UInt8:
    """Convert a 6-bit value to its Base64URL character."""
    var chars = BASE64URL_CHARS
    return ord(chars[index])


fn base64url_encode(data: List[UInt8]) -> String:
    """Encode bytes to Base64URL string (no padding).

    Args:
        data: Raw bytes to encode.

    Returns:
        Base64URL encoded string without padding.
    """
    if len(data) == 0:
        return ""

    var result = String()
    var i = 0
    var length = len(data)

    # Process 3 bytes at a time
    while i + 2 < length:
        var b0 = int(data[i])
        var b1 = int(data[i + 1])
        var b2 = int(data[i + 2])

        # Combine 3 bytes into 4 6-bit groups
        var c0 = (b0 >> 2) & 0x3F
        var c1 = ((b0 << 4) | (b1 >> 4)) & 0x3F
        var c2 = ((b1 << 2) | (b2 >> 6)) & 0x3F
        var c3 = b2 & 0x3F

        result += chr(int(_index_to_char(c0)))
        result += chr(int(_index_to_char(c1)))
        result += chr(int(_index_to_char(c2)))
        result += chr(int(_index_to_char(c3)))

        i += 3

    # Handle remaining bytes (no padding in Base64URL)
    var remaining = length - i
    if remaining == 1:
        var b0 = int(data[i])
        var c0 = (b0 >> 2) & 0x3F
        var c1 = (b0 << 4) & 0x3F
        result += chr(int(_index_to_char(c0)))
        result += chr(int(_index_to_char(c1)))
    elif remaining == 2:
        var b0 = int(data[i])
        var b1 = int(data[i + 1])
        var c0 = (b0 >> 2) & 0x3F
        var c1 = ((b0 << 4) | (b1 >> 4)) & 0x3F
        var c2 = (b1 << 2) & 0x3F
        result += chr(int(_index_to_char(c0)))
        result += chr(int(_index_to_char(c1)))
        result += chr(int(_index_to_char(c2)))

    return result


fn base64url_encode_string(s: String) -> String:
    """Encode a string to Base64URL.

    Args:
        s: String to encode.

    Returns:
        Base64URL encoded string.
    """
    var data = List[UInt8]()
    for i in range(len(s)):
        data.append(ord(s[i]))
    return base64url_encode(data)


fn base64url_decode(encoded: String) -> JWTResult[List[UInt8]]:
    """Decode a Base64URL string to bytes.

    Args:
        encoded: Base64URL encoded string (with or without padding).

    Returns:
        Decoded bytes or error.
    """
    if len(encoded) == 0:
        return JWTResult[List[UInt8]].ok(List[UInt8]())

    # Remove any padding (shouldn't be there in Base64URL, but handle it)
    var input_str = encoded
    while len(input_str) > 0 and input_str[len(input_str) - 1] == "=":
        input_str = input_str[: len(input_str) - 1]

    var result = List[UInt8]()
    var length = len(input_str)
    var i = 0

    # Process 4 characters at a time
    while i + 3 < length:
        var c0 = _char_to_index(ord(input_str[i]))
        var c1 = _char_to_index(ord(input_str[i + 1]))
        var c2 = _char_to_index(ord(input_str[i + 2]))
        var c3 = _char_to_index(ord(input_str[i + 3]))

        if c0 < 0 or c1 < 0 or c2 < 0 or c3 < 0:
            return JWTResult[List[UInt8]].err(
                JWTError.invalid_base64("Invalid character in Base64URL string")
            )

        # Combine 4 6-bit values into 3 bytes
        result.append(UInt8(((c0 << 2) | (c1 >> 4)) & 0xFF))
        result.append(UInt8(((c1 << 4) | (c2 >> 2)) & 0xFF))
        result.append(UInt8(((c2 << 6) | c3) & 0xFF))

        i += 4

    # Handle remaining characters
    var remaining = length - i
    if remaining == 2:
        var c0 = _char_to_index(ord(input_str[i]))
        var c1 = _char_to_index(ord(input_str[i + 1]))
        if c0 < 0 or c1 < 0:
            return JWTResult[List[UInt8]].err(
                JWTError.invalid_base64("Invalid character in Base64URL string")
            )
        result.append(UInt8(((c0 << 2) | (c1 >> 4)) & 0xFF))
    elif remaining == 3:
        var c0 = _char_to_index(ord(input_str[i]))
        var c1 = _char_to_index(ord(input_str[i + 1]))
        var c2 = _char_to_index(ord(input_str[i + 2]))
        if c0 < 0 or c1 < 0 or c2 < 0:
            return JWTResult[List[UInt8]].err(
                JWTError.invalid_base64("Invalid character in Base64URL string")
            )
        result.append(UInt8(((c0 << 2) | (c1 >> 4)) & 0xFF))
        result.append(UInt8(((c1 << 4) | (c2 >> 2)) & 0xFF))
    elif remaining == 1:
        # Invalid: single character cannot encode anything useful
        return JWTResult[List[UInt8]].err(
            JWTError.invalid_base64("Invalid Base64URL length")
        )

    return JWTResult[List[UInt8]].ok(result)


fn base64url_decode_to_string(encoded: String) -> JWTResult[String]:
    """Decode a Base64URL string to a UTF-8 string.

    Args:
        encoded: Base64URL encoded string.

    Returns:
        Decoded string or error.
    """
    var bytes_result = base64url_decode(encoded)
    if bytes_result.is_err():
        return JWTResult[String].err(bytes_result.error())

    var bytes = bytes_result.value()
    var result = String()
    for i in range(len(bytes)):
        result += chr(int(bytes[i]))

    return JWTResult[String].ok(result)


fn bytes_equal(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Compare two byte arrays in constant time (to prevent timing attacks).

    Security Note:
        This function avoids early returns that could leak timing information.
        The length difference is XORed into the result rather than causing
        an early return, ensuring consistent execution time regardless of
        where the first difference occurs.

    Args:
        a: First byte array.
        b: Second byte array.

    Returns:
        True if arrays are equal in both length and content.
    """
    # XOR length difference into result (avoids timing leak from early return)
    var result: UInt8 = 0
    if len(a) != len(b):
        result = 1

    # Compare all bytes up to the shorter length
    var min_len = min(len(a), len(b))
    for i in range(min_len):
        result |= a[i] ^ b[i]

    return result == 0
