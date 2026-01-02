"""Pure Mojo implementation of SHA-256 hash algorithm.

This implements the SHA-256 cryptographic hash function as specified in
FIPS PUB 180-4 (Secure Hash Standard).
"""


# SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
alias H0: UInt32 = 0x6A09E667
alias H1: UInt32 = 0xBB67AE85
alias H2: UInt32 = 0x3C6EF372
alias H3: UInt32 = 0xA54FF53A
alias H4: UInt32 = 0x510E527F
alias H5: UInt32 = 0x9B05688C
alias H6: UInt32 = 0x1F83D9AB
alias H7: UInt32 = 0x5BE0CD19


fn _get_k(i: Int) -> UInt32:
    """Get the round constant K[i] for SHA-256.
    These are the first 32 bits of the fractional parts of the cube roots of the first 64 primes."""
    # Round constants (K values)
    if i == 0:
        return 0x428A2F98
    elif i == 1:
        return 0x71374491
    elif i == 2:
        return 0xB5C0FBCF
    elif i == 3:
        return 0xE9B5DBA5
    elif i == 4:
        return 0x3956C25B
    elif i == 5:
        return 0x59F111F1
    elif i == 6:
        return 0x923F82A4
    elif i == 7:
        return 0xAB1C5ED5
    elif i == 8:
        return 0xD807AA98
    elif i == 9:
        return 0x12835B01
    elif i == 10:
        return 0x243185BE
    elif i == 11:
        return 0x550C7DC3
    elif i == 12:
        return 0x72BE5D74
    elif i == 13:
        return 0x80DEB1FE
    elif i == 14:
        return 0x9BDC06A7
    elif i == 15:
        return 0xC19BF174
    elif i == 16:
        return 0xE49B69C1
    elif i == 17:
        return 0xEFBE4786
    elif i == 18:
        return 0x0FC19DC6
    elif i == 19:
        return 0x240CA1CC
    elif i == 20:
        return 0x2DE92C6F
    elif i == 21:
        return 0x4A7484AA
    elif i == 22:
        return 0x5CB0A9DC
    elif i == 23:
        return 0x76F988DA
    elif i == 24:
        return 0x983E5152
    elif i == 25:
        return 0xA831C66D
    elif i == 26:
        return 0xB00327C8
    elif i == 27:
        return 0xBF597FC7
    elif i == 28:
        return 0xC6E00BF3
    elif i == 29:
        return 0xD5A79147
    elif i == 30:
        return 0x06CA6351
    elif i == 31:
        return 0x14292967
    elif i == 32:
        return 0x27B70A85
    elif i == 33:
        return 0x2E1B2138
    elif i == 34:
        return 0x4D2C6DFC
    elif i == 35:
        return 0x53380D13
    elif i == 36:
        return 0x650A7354
    elif i == 37:
        return 0x766A0ABB
    elif i == 38:
        return 0x81C2C92E
    elif i == 39:
        return 0x92722C85
    elif i == 40:
        return 0xA2BFE8A1
    elif i == 41:
        return 0xA81A664B
    elif i == 42:
        return 0xC24B8B70
    elif i == 43:
        return 0xC76C51A3
    elif i == 44:
        return 0xD192E819
    elif i == 45:
        return 0xD6990624
    elif i == 46:
        return 0xF40E3585
    elif i == 47:
        return 0x106AA070
    elif i == 48:
        return 0x19A4C116
    elif i == 49:
        return 0x1E376C08
    elif i == 50:
        return 0x2748774C
    elif i == 51:
        return 0x34B0BCB5
    elif i == 52:
        return 0x391C0CB3
    elif i == 53:
        return 0x4ED8AA4A
    elif i == 54:
        return 0x5B9CCA4F
    elif i == 55:
        return 0x682E6FF3
    elif i == 56:
        return 0x748F82EE
    elif i == 57:
        return 0x78A5636F
    elif i == 58:
        return 0x84C87814
    elif i == 59:
        return 0x8CC70208
    elif i == 60:
        return 0x90BEFFFA
    elif i == 61:
        return 0xA4506CEB
    elif i == 62:
        return 0xBEF9A3F7
    elif i == 63:
        return 0xC67178F2
    else:
        return 0


fn _rotr(x: UInt32, n: Int) -> UInt32:
    """Rotate right (circular right shift)."""
    return (x >> n) | (x << (32 - n))


fn _ch(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    """Choice function: if x then y else z."""
    return (x & y) ^ (~x & z)


fn _maj(x: UInt32, y: UInt32, z: UInt32) -> UInt32:
    """Majority function: majority of x, y, z."""
    return (x & y) ^ (x & z) ^ (y & z)


fn _sigma0(x: UInt32) -> UInt32:
    """SHA-256 Sigma0 function."""
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)


fn _sigma1(x: UInt32) -> UInt32:
    """SHA-256 Sigma1 function."""
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)


fn _gamma0(x: UInt32) -> UInt32:
    """SHA-256 lowercase sigma0 (for message schedule)."""
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)


fn _gamma1(x: UInt32) -> UInt32:
    """SHA-256 lowercase sigma1 (for message schedule)."""
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


@value
struct SHA256:
    """SHA-256 hash computation state."""

    var h0: UInt32
    var h1: UInt32
    var h2: UInt32
    var h3: UInt32
    var h4: UInt32
    var h5: UInt32
    var h6: UInt32
    var h7: UInt32
    var buffer: List[UInt8]
    var total_length: UInt64

    fn __init__(out self):
        """Initialize SHA-256 state with initial hash values."""
        self.h0 = H0
        self.h1 = H1
        self.h2 = H2
        self.h3 = H3
        self.h4 = H4
        self.h5 = H5
        self.h6 = H6
        self.h7 = H7
        self.buffer = List[UInt8]()
        self.total_length = 0

    fn update(mut self, data: List[UInt8]):
        """Add data to the hash computation.

        Args:
            data: Bytes to add to the hash.
        """
        self.total_length += len(data)

        # Add data to buffer
        for i in range(len(data)):
            self.buffer.append(data[i])

        # Process complete 64-byte blocks
        while len(self.buffer) >= 64:
            self._process_block()

    fn update_string(mut self, s: String):
        """Add string data to the hash computation.

        Args:
            s: String to add to the hash.
        """
        var data = List[UInt8]()
        for i in range(len(s)):
            data.append(ord(s[i]))
        self.update(data)

    fn _process_block(mut self):
        """Process a 64-byte block from the buffer."""
        # Create message schedule array (64 32-bit words)
        var w = List[UInt32]()
        for _ in range(64):
            w.append(0)

        # Copy block into first 16 words (big-endian)
        for i in range(16):
            var offset = i * 4
            w[i] = (
                (UInt32(self.buffer[offset]) << 24)
                | (UInt32(self.buffer[offset + 1]) << 16)
                | (UInt32(self.buffer[offset + 2]) << 8)
                | UInt32(self.buffer[offset + 3])
            )

        # Extend the first 16 words into the remaining 48 words
        for i in range(16, 64):
            w[i] = _gamma1(w[i - 2]) + w[i - 7] + _gamma0(w[i - 15]) + w[i - 16]

        # Initialize working variables
        var a = self.h0
        var b = self.h1
        var c = self.h2
        var d = self.h3
        var e = self.h4
        var f = self.h5
        var g = self.h6
        var h = self.h7

        # Main compression loop
        for i in range(64):
            var t1 = h + _sigma1(e) + _ch(e, f, g) + _get_k(i) + w[i]
            var t2 = _sigma0(a) + _maj(a, b, c)

            h = g
            g = f
            f = e
            e = d + t1
            d = c
            c = b
            b = a
            a = t1 + t2

        # Add compressed chunk to current hash value
        self.h0 += a
        self.h1 += b
        self.h2 += c
        self.h3 += d
        self.h4 += e
        self.h5 += f
        self.h6 += g
        self.h7 += h

        # Remove processed block from buffer
        var new_buffer = List[UInt8]()
        for i in range(64, len(self.buffer)):
            new_buffer.append(self.buffer[i])
        self.buffer = new_buffer

    fn finalize(mut self) -> List[UInt8]:
        """Finalize the hash computation and return the digest.

        Returns:
            32-byte SHA-256 hash.
        """
        # Calculate the original message length in bits
        var bit_length = self.total_length * 8

        # Append padding
        # Add the '1' bit (0x80)
        self.buffer.append(0x80)

        # Pad with zeros until length is 56 mod 64
        while len(self.buffer) % 64 != 56:
            self.buffer.append(0x00)

        # Append original length as 64-bit big-endian integer
        self.buffer.append(UInt8((bit_length >> 56) & 0xFF))
        self.buffer.append(UInt8((bit_length >> 48) & 0xFF))
        self.buffer.append(UInt8((bit_length >> 40) & 0xFF))
        self.buffer.append(UInt8((bit_length >> 32) & 0xFF))
        self.buffer.append(UInt8((bit_length >> 24) & 0xFF))
        self.buffer.append(UInt8((bit_length >> 16) & 0xFF))
        self.buffer.append(UInt8((bit_length >> 8) & 0xFF))
        self.buffer.append(UInt8(bit_length & 0xFF))

        # Process remaining blocks
        while len(self.buffer) >= 64:
            self._process_block()

        # Produce the final hash value (big-endian)
        var result = List[UInt8]()
        result.append(UInt8((self.h0 >> 24) & 0xFF))
        result.append(UInt8((self.h0 >> 16) & 0xFF))
        result.append(UInt8((self.h0 >> 8) & 0xFF))
        result.append(UInt8(self.h0 & 0xFF))
        result.append(UInt8((self.h1 >> 24) & 0xFF))
        result.append(UInt8((self.h1 >> 16) & 0xFF))
        result.append(UInt8((self.h1 >> 8) & 0xFF))
        result.append(UInt8(self.h1 & 0xFF))
        result.append(UInt8((self.h2 >> 24) & 0xFF))
        result.append(UInt8((self.h2 >> 16) & 0xFF))
        result.append(UInt8((self.h2 >> 8) & 0xFF))
        result.append(UInt8(self.h2 & 0xFF))
        result.append(UInt8((self.h3 >> 24) & 0xFF))
        result.append(UInt8((self.h3 >> 16) & 0xFF))
        result.append(UInt8((self.h3 >> 8) & 0xFF))
        result.append(UInt8(self.h3 & 0xFF))
        result.append(UInt8((self.h4 >> 24) & 0xFF))
        result.append(UInt8((self.h4 >> 16) & 0xFF))
        result.append(UInt8((self.h4 >> 8) & 0xFF))
        result.append(UInt8(self.h4 & 0xFF))
        result.append(UInt8((self.h5 >> 24) & 0xFF))
        result.append(UInt8((self.h5 >> 16) & 0xFF))
        result.append(UInt8((self.h5 >> 8) & 0xFF))
        result.append(UInt8(self.h5 & 0xFF))
        result.append(UInt8((self.h6 >> 24) & 0xFF))
        result.append(UInt8((self.h6 >> 16) & 0xFF))
        result.append(UInt8((self.h6 >> 8) & 0xFF))
        result.append(UInt8(self.h6 & 0xFF))
        result.append(UInt8((self.h7 >> 24) & 0xFF))
        result.append(UInt8((self.h7 >> 16) & 0xFF))
        result.append(UInt8((self.h7 >> 8) & 0xFF))
        result.append(UInt8(self.h7 & 0xFF))

        return result


fn sha256(data: List[UInt8]) -> List[UInt8]:
    """Compute SHA-256 hash of data.

    Args:
        data: Input bytes.

    Returns:
        32-byte SHA-256 hash.
    """
    var hasher = SHA256()
    hasher.update(data)
    return hasher.finalize()


fn sha256_string(s: String) -> List[UInt8]:
    """Compute SHA-256 hash of a string.

    Args:
        s: Input string.

    Returns:
        32-byte SHA-256 hash.
    """
    var hasher = SHA256()
    hasher.update_string(s)
    return hasher.finalize()


fn sha256_hex(data: List[UInt8]) -> String:
    """Compute SHA-256 hash and return as hex string.

    Args:
        data: Input bytes.

    Returns:
        64-character hexadecimal string.
    """
    var hash = sha256(data)
    return bytes_to_hex(hash)


fn bytes_to_hex(data: List[UInt8]) -> String:
    """Convert bytes to hexadecimal string.

    Args:
        data: Input bytes.

    Returns:
        Hexadecimal string (2 chars per byte).
    """
    alias HEX_CHARS = "0123456789abcdef"
    var result = String()
    for i in range(len(data)):
        var b = int(data[i])
        result += HEX_CHARS[(b >> 4) & 0x0F]
        result += HEX_CHARS[b & 0x0F]
    return result
