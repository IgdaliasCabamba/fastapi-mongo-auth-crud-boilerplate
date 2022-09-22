import base64
from pprint import pprint
from typing import List

import fastapi_jwt_auth.exceptions
from bson.objectid import ObjectId
from fastapi import Depends, HTTPException, status
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from ..serializers.oauth2_serializer import user_entity
from ..utils.config import settings
from .database import User


class Settings(BaseModel):
    authjwt_algorithm: str = settings.JWT_ALGORITHM
    authjwt_decode_algorithms: List[str] = [settings.JWT_ALGORITHM]
    authjwt_token_location: set = {'cookies', 'headers'}
    authjwt_access_cookie_key: str = 'access_token'
    authjwt_refresh_cookie_key: str = 'refresh_token'
    authjwt_cookie_csrf_protect: bool = False
    authjwt_public_key: str = base64.b64decode(settings.JWT_PUBLIC_KEY).decode('utf-8')
    authjwt_private_key: str = base64.b64decode(settings.JWT_PRIVATE_KEY).decode('utf-8')


@AuthJWT.load_config
def get_config():
    return Settings()


class NotVerified(Exception):
    pass


class UserNotFound(Exception):
    pass


def require_user(Authorize: AuthJWT = Depends()) -> int:
    try:
        Authorize.jwt_required()
        user_id = Authorize.get_jwt_subject()
        user = user_entity(User.find_one({'_id': ObjectId(str(user_id))}))

        if not user:
            raise UserNotFound('User no longer exist')

        if not user["verified"]:
            raise NotVerified('You are not verified')

    except fastapi_jwt_auth.exceptions.MissingTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='You are not logged in')

    except UserNotFound:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='User no longer exist')

    except NotVerified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Please verify your account')
    
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Token is invalid or has expired')

    return user_id
