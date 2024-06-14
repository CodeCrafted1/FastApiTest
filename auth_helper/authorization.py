import os
import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta
from settings import Settings

class Authorization:
    def __init__(self):
        self.hasher = CryptContext(schemes=['bcrypt'])
        self.secret = Settings.SECRET_KEY

    def encode_password(self, password: str) -> str:
        return self.hasher.hash(password)

    def verify_password(self, password: str, encoded_password: str) -> bool:
        return self.hasher.verify(password, encoded_password)

    def _encode_token(self, id: str, exp_delta: timedelta, scope: str) -> str:
        payload = {
            'exp': datetime.utcnow() + exp_delta,
            'iat': datetime.utcnow(),
            'scope': scope,
            'sub': id
        }
        return jwt.encode(payload, self.secret, algorithm='HS256')

    def encode_token(self, id: str) -> str:
        return self._encode_token(id, timedelta(minutes=30), 'access_token')

    def encode_refresh_token(self, id: str) -> str:
        return self._encode_token(id, timedelta(hours=10), 'refresh_token')

    def _decode_token(self, token: str, scope: str) -> str:
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            if payload['scope'] == scope:
                return payload['sub']
            raise HTTPException(status_code=401, detail='Scope for the token is invalid')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401, detail=f'Invalid token {e}')

    def decode_token(self, token: str) -> str:
        return self._decode_token(token, 'access_token')

    def refresh_token(self, refresh_token: str) -> tuple[str, str]:
        id = self._decode_token(refresh_token, 'refresh_token')
        new_access_token = self.encode_token(id)
        new_refresh_token = self.encode_refresh_token(id)
        return new_access_token, new_refresh_token
