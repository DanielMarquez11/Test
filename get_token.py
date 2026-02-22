import hashlib
import hmac
import os
import secrets
import time


def generate_token(user_id: str, secret_key: str) -> tuple:
    """Generate a cryptographically secure authentication token for a given user.

    Returns a tuple of (token, issued_at) where token encodes a nonce and timestamp.
    """
    if not user_id or not user_id.strip():
        raise ValueError("user_id must not be empty")
    if not secret_key or not secret_key.strip():
        raise ValueError("secret_key must not be empty")
    issued_at = int(time.time())
    nonce = secrets.token_hex(16)
    raw = f"{user_id}:{issued_at}:{nonce}"
    signature = hmac.new(secret_key.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{nonce}.{issued_at}.{signature}", issued_at


def get_token(user_id: str, secret_key: str) -> dict:
    """Retrieve an authentication token for the given user ID."""
    token, issued_at = generate_token(user_id, secret_key)
    return {
        "user_id": user_id,
        "token": token,
        "issued_at": issued_at,
    }


if __name__ == "__main__":
    import sys

    secret = os.environ.get("TOKEN_SECRET_KEY")
    if not secret:
        print("Error: TOKEN_SECRET_KEY environment variable is required.", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python get_token.py <user_id>", file=sys.stderr)
        sys.exit(1)

    user = sys.argv[1].strip()
    if not user:
        print("Error: user_id must not be empty.", file=sys.stderr)
        sys.exit(1)

    result = get_token(user, secret)
    print(f"User:       {result['user_id']}")
    print(f"Token:      {result['token']}")
    print(f"Issued at:  {result['issued_at']}")



if __name__ == "__main__":
    import sys

    secret = os.environ.get("TOKEN_SECRET_KEY")
    if not secret:
        print("Error: TOKEN_SECRET_KEY environment variable is required.", file=sys.stderr)
        sys.exit(1)

    if len(sys.argv) < 2:
        print("Usage: python get_token.py <user_id>", file=sys.stderr)
        sys.exit(1)

    user = sys.argv[1].strip()
    if not user:
        print("Error: user_id must not be empty.", file=sys.stderr)
        sys.exit(1)

    result = get_token(user, secret)
    print(f"User:       {result['user_id']}")
    print(f"Token:      {result['token']}")
    print(f"Issued at:  {result['issued_at']}")
