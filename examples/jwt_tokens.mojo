"""JWT token creation and validation."""
from mojo_jwt import JWT, JWTHeader, JWTPayload, encode_jwt, decode_jwt

fn main() raises:
    var secret = "your-256-bit-secret-key-here!!"
    
    # Create JWT payload
    var payload = JWTPayload()
    payload.set_subject("user123")
    payload.set_issuer("my-app")
    payload.set_claim("role", "admin")
    
    # Encode token
    var token = encode_jwt(payload, secret)
    print("JWT Token:", token[:50], "...")
    
    # Decode and verify
    var decoded = decode_jwt(token, secret)
    if decoded.is_valid():
        print("Subject:", decoded.payload.subject())
        print("Role:", decoded.payload.get_claim("role"))
    else:
        print("Invalid token!")
