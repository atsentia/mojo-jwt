"""JWT error types for validation failures."""


@value
struct JWTErrorKind(Stringable):
    """Enumeration of JWT error types."""

    var value: Int

    alias INVALID_FORMAT = JWTErrorKind(0)
    alias INVALID_BASE64 = JWTErrorKind(1)
    alias INVALID_HEADER = JWTErrorKind(2)
    alias INVALID_PAYLOAD = JWTErrorKind(3)
    alias INVALID_SIGNATURE = JWTErrorKind(4)
    alias UNSUPPORTED_ALGORITHM = JWTErrorKind(5)
    alias TOKEN_EXPIRED = JWTErrorKind(6)
    alias TOKEN_NOT_YET_VALID = JWTErrorKind(7)
    alias INVALID_ISSUER = JWTErrorKind(8)
    alias INVALID_AUDIENCE = JWTErrorKind(9)
    alias MISSING_CLAIM = JWTErrorKind(10)

    fn __str__(self) -> String:
        if self.value == 0:
            return "INVALID_FORMAT"
        elif self.value == 1:
            return "INVALID_BASE64"
        elif self.value == 2:
            return "INVALID_HEADER"
        elif self.value == 3:
            return "INVALID_PAYLOAD"
        elif self.value == 4:
            return "INVALID_SIGNATURE"
        elif self.value == 5:
            return "UNSUPPORTED_ALGORITHM"
        elif self.value == 6:
            return "TOKEN_EXPIRED"
        elif self.value == 7:
            return "TOKEN_NOT_YET_VALID"
        elif self.value == 8:
            return "INVALID_ISSUER"
        elif self.value == 9:
            return "INVALID_AUDIENCE"
        elif self.value == 10:
            return "MISSING_CLAIM"
        else:
            return "UNKNOWN_ERROR"

    fn __eq__(self, other: Self) -> Bool:
        return self.value == other.value

    fn __ne__(self, other: Self) -> Bool:
        return self.value != other.value


@value
struct JWTError(Stringable):
    """JWT validation error with kind and message."""

    var kind: JWTErrorKind
    var message: String

    fn __init__(out self, kind: JWTErrorKind, message: String = ""):
        self.kind = kind
        if message:
            self.message = message
        else:
            self.message = str(kind)

    fn __str__(self) -> String:
        return "JWTError(" + str(self.kind) + "): " + self.message

    @staticmethod
    fn invalid_format(message: String = "Invalid JWT format") -> Self:
        return JWTError(JWTErrorKind.INVALID_FORMAT, message)

    @staticmethod
    fn invalid_base64(message: String = "Invalid Base64URL encoding") -> Self:
        return JWTError(JWTErrorKind.INVALID_BASE64, message)

    @staticmethod
    fn invalid_header(message: String = "Invalid JWT header") -> Self:
        return JWTError(JWTErrorKind.INVALID_HEADER, message)

    @staticmethod
    fn invalid_payload(message: String = "Invalid JWT payload") -> Self:
        return JWTError(JWTErrorKind.INVALID_PAYLOAD, message)

    @staticmethod
    fn invalid_signature(message: String = "Invalid signature") -> Self:
        return JWTError(JWTErrorKind.INVALID_SIGNATURE, message)

    @staticmethod
    fn unsupported_algorithm(alg: String) -> Self:
        return JWTError(
            JWTErrorKind.UNSUPPORTED_ALGORITHM,
            "Unsupported algorithm: " + alg,
        )

    @staticmethod
    fn token_expired() -> Self:
        return JWTError(JWTErrorKind.TOKEN_EXPIRED, "Token has expired")

    @staticmethod
    fn token_not_yet_valid() -> Self:
        return JWTError(
            JWTErrorKind.TOKEN_NOT_YET_VALID, "Token is not yet valid"
        )

    @staticmethod
    fn invalid_issuer(expected: String, actual: String) -> Self:
        return JWTError(
            JWTErrorKind.INVALID_ISSUER,
            "Invalid issuer: expected '" + expected + "', got '" + actual + "'",
        )

    @staticmethod
    fn invalid_audience(expected: String, actual: String) -> Self:
        return JWTError(
            JWTErrorKind.INVALID_AUDIENCE,
            "Invalid audience: expected '"
            + expected
            + "', got '"
            + actual
            + "'",
        )

    @staticmethod
    fn missing_claim(claim: String) -> Self:
        return JWTError(
            JWTErrorKind.MISSING_CLAIM, "Missing required claim: " + claim
        )


@value
struct JWTResult[T: Movable & Copyable](Stringable):
    """Result type for JWT operations - either success value or error."""

    var _value: T
    var _error: JWTError
    var _is_ok: Bool

    fn __init__(out self, value: T):
        """Create a successful result."""
        self._value = value
        self._error = JWTError(JWTErrorKind.INVALID_FORMAT, "")
        self._is_ok = True

    @staticmethod
    fn ok(value: T) -> Self:
        """Create a successful result."""
        return Self(value)

    @staticmethod
    fn err(error: JWTError) -> Self:
        """Create an error result."""
        var result = Self.__new__()
        result._is_ok = False
        result._error = error
        return result

    @staticmethod
    fn __new__() -> Self:
        """Internal: create uninitialized result."""
        var result: Self
        result._is_ok = False
        result._error = JWTError(JWTErrorKind.INVALID_FORMAT, "")
        # Note: _value will be uninitialized, only access if _is_ok
        return result^

    fn is_ok(self) -> Bool:
        """Check if result is successful."""
        return self._is_ok

    fn is_err(self) -> Bool:
        """Check if result is an error."""
        return not self._is_ok

    fn value(self) -> T:
        """Get the success value. Only call if is_ok() is True."""
        return self._value

    fn error(self) -> JWTError:
        """Get the error. Only call if is_err() is True."""
        return self._error

    fn __str__(self) -> String:
        if self._is_ok:
            return "Ok(...)"
        else:
            return "Err(" + str(self._error) + ")"
