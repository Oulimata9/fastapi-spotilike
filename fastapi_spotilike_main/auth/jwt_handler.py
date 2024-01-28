# This file is responsible for signing, encoding, decoding and returning JWTs.
import time
import jwt
from decouple import config
from typing import Mapping


JWT_SECRET = config("JWT_SECRET", default="ea504dfd74cdc3fbddcb4e67c73b6070")
JWT_ALGORITHM = "HS256"

# Function returns the generated Tokens (JWTs)
def token_response (token: str):
    return {
        "access token" : token
    }
# Function used for signing the JWT string
def signIW(userID : str):
    payload = {
        "userID" : userID,
        "expiry" : time.time() + 600
    } 
    token = jwt. encode(payload, JWT_SECRET, algorith=JWT_ALGORITHM)
    return token_response(token)

def decodeJWT(token: str) -> Mapping:
    try:
        decode_token: Mapping = jwt.decode(token, JWT_SECRET, algorithm=JWT_ALGORITHM)
        return decode_token if decode_token['expires'] >= time.time() else None
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
       
        return None