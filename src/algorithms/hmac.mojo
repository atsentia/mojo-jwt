"""HMAC (Hash-based Message Authentication Code) implementation.

Implements HMAC as specified in RFC 2104 using SHA-256 as the underlying hash.
HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
where:
  - K' is the key padded/hashed to block size (64 bytes for SHA-256)
  - ipad is 0x36 repeated 64 times
  - opad is 0x5c repeated 64 times
"""

from .sha256 import SHA256, sha256


alias BLOCK_SIZE = 64  # SHA-256 block size in bytes
alias IPAD: UInt8 = 0x36
alias OPAD: UInt8 = 0x5C


fn hmac_sha256(key: List[UInt8], message: List[UInt8]) -> List[UInt8]:
    """Compute HMAC-SHA256 of a message with a key.

    Args:
        key: Secret key (any length).
        message: Message to authenticate.

    Returns:
        32-byte HMAC-SHA256 result.
    """
    # Step 1: Normalize key to block size
    var normalized_key = _normalize_key(key)

    # Step 2: Create inner and outer padded keys
    var inner_key = List[UInt8]()
    var outer_key = List[UInt8]()

    for i in range(BLOCK_SIZE):
        inner_key.append(normalized_key[i] ^ IPAD)
        outer_key.append(normalized_key[i] ^ OPAD)

    # Step 3: Compute inner hash: H((K' XOR ipad) || message)
    var inner_hasher = SHA256()

    # Add inner padded key
    inner_hasher.update(inner_key)

    # Add message
    inner_hasher.update(message)

    var inner_hash = inner_hasher.finalize()

    # Step 4: Compute outer hash: H((K' XOR opad) || inner_hash)
    var outer_hasher = SHA256()

    # Add outer padded key
    outer_hasher.update(outer_key)

    # Add inner hash result
    outer_hasher.update(inner_hash)

    return outer_hasher.finalize()


fn hmac_sha256_string(key: String, message: String) -> List[UInt8]:
    """Compute HMAC-SHA256 of a message string with a key string.

    Args:
        key: Secret key as string.
        message: Message to authenticate as string.

    Returns:
        32-byte HMAC-SHA256 result.
    """
    var key_bytes = _string_to_bytes(key)
    var message_bytes = _string_to_bytes(message)
    return hmac_sha256(key_bytes, message_bytes)


fn _normalize_key(key: List[UInt8]) -> List[UInt8]:
    """Normalize key to exactly BLOCK_SIZE bytes.

    If key is longer than block size, hash it.
    If key is shorter, pad with zeros.

    Args:
        key: Input key of any length.

    Returns:
        Key normalized to BLOCK_SIZE bytes.
    """
    var result = List[UInt8]()

    if len(key) > BLOCK_SIZE:
        # Key is too long: hash it to get 32 bytes, then pad
        var hashed = sha256(key)
        for i in range(len(hashed)):
            result.append(hashed[i])
        # Pad with zeros to reach block size
        for _ in range(BLOCK_SIZE - 32):
            result.append(0)
    elif len(key) < BLOCK_SIZE:
        # Key is too short: copy and pad with zeros
        for i in range(len(key)):
            result.append(key[i])
        for _ in range(BLOCK_SIZE - len(key)):
            result.append(0)
    else:
        # Key is exactly block size
        for i in range(len(key)):
            result.append(key[i])

    return result


fn _string_to_bytes(s: String) -> List[UInt8]:
    """Convert a string to a byte list.

    Args:
        s: Input string.

    Returns:
        Bytes of the string.
    """
    var result = List[UInt8]()
    for i in range(len(s)):
        result.append(ord(s[i]))
    return result


fn hmac_sha256_verify(
    key: List[UInt8], message: List[UInt8], expected_mac: List[UInt8]
) -> Bool:
    """Verify HMAC-SHA256 in constant time.

    Args:
        key: Secret key.
        message: Message that was authenticated.
        expected_mac: Expected MAC value.

    Returns:
        True if MAC is valid, False otherwise.
    """
    var computed_mac = hmac_sha256(key, message)
    return _constant_time_compare(computed_mac, expected_mac)


fn _constant_time_compare(a: List[UInt8], b: List[UInt8]) -> Bool:
    """Compare two byte arrays in constant time to prevent timing attacks.

    Args:
        a: First byte array.
        b: Second byte array.

    Returns:
        True if arrays are equal.
    """
    if len(a) != len(b):
        return False

    var result: UInt8 = 0
    for i in range(len(a)):
        result |= a[i] ^ b[i]

    return result == 0
