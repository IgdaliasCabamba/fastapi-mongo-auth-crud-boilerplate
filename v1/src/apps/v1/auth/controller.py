import hashlib
import secrets
from datetime import datetime, timedelta
from pprint import pprint
from typing import Any

from bson.objectid import ObjectId
from fastapi import (BackgroundTasks, Depends, HTTPException, Request,
                     Response, status)
from fastapi.responses import ORJSONResponse
from pydantic import EmailStr
from src.utils import email, oauth2, security
from src.utils.config import settings
from src.utils.database import User
from src.utils.oauth2 import AuthJWT
from typing_extensions import Self

from . import schemas
from .serializers import user_entity, user_response_entity

ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


def __get_days_to_secods(days: int) -> int:
    if isinstance(days, int):
        return days * 60 * 24
    return 1 * 60 * 24  # 1 day


class EmailAuthUtils:

    class NotSent(Exception):
        ...

    def __init__(self, request: Request, background_tasks: BackgroundTasks, payload: schemas.CreateUserSchema) -> None:
        self._request = request
        self._background_tasks = background_tasks
        self._payload = payload
        self.__cached_token_and_verification_code = None

    @property
    def token_and_verification_code(self) -> tuple:
        if self.__cached_token_and_verification_code is None:
            token = secrets.token_bytes(10)
            hashedCode = hashlib.sha256()
            hashedCode.update(token)
            verification_code = hashedCode.hexdigest()

            token_and_verification_code = (token, verification_code)
            self.__cached_token_and_verification_code = token_and_verification_code

            return token_and_verification_code

        return self.__cached_token_and_verification_code

    def send_verification_code(self, inserted_id: int, new_user: dict) -> Self:
        try:
            token, verification_code = self.token_and_verification_code

            User.find_one_and_update({"_id": inserted_id}, {
                "$set": {"verification_code": verification_code, "updated_at": datetime.utcnow()}})

            url = f"{self._request.url.scheme}://{self._request.client.host}:{self._request.url.port}/api/v1/auth/verifyemail/{token.hex()}"
            self._background_tasks.add_task(email.Email(
                new_user, url, [EmailStr(self._payload.email)]).send_verification_code)
        except:
            User.find_one_and_update({"_id": inserted_id}, {
                "$set": {"verification_code": None, "updated_at": datetime.utcnow()}})
            raise EmailAuthUtils.NotSent()

        return self

    @staticmethod
    def get_verification_code_from_token(token: str) -> str:
        hashedCode = hashlib.sha256()
        hashedCode.update(bytes.fromhex(token))
        return hashedCode.hexdigest()

    @staticmethod
    def verify_user_by_verification_code(code: str) -> Any:
        return User.find_one_and_update({"verification_code": code}, {
            "$set": {"verification_code": None, "verified": True, "updated_at": datetime.utcnow()}}, new=True)


class UserAuthUtils:

    def __init__(self, user: dict, payload: schemas.CreateUserSchema) -> None:
        self._user = user
        self._payload = payload
        self.__cached_dict_payload = None

    def user_does_not_exist_yet(self) -> Self:
        if self._user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail='Account already exist')
        return self

    def password_and_password_confirmation_are_the_same(self) -> Self:
        if self._payload.password != self._payload.passwordConfirm:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Passwords do not match')
        return self

    def user_exist(self) -> Self:
        if not self._user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Incorrect Email or Password')
        return self

    def is_email_verified(self) -> Self:
        if not self._user['verified']:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Please verify your email address')
        return self

    def is_password_valid(self) -> Self:
        if not security.verify_password(self._payload.password, self._user['password']):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Incorrect Email or Password')
        return self

    @property
    def user_payload(self) -> dict:

        if self.__cached_dict_payload is not None:
            return self.__cached_dict_payload

        _payload = self._payload.copy()
        _payload.password = security.hash_password(_payload.password)
        del _payload.passwordConfirm
        _payload.role = 'user'
        _payload.verified = False
        _payload.email = _payload.email.lower()
        _payload.created_at = datetime.utcnow()
        _payload.updated_at = _payload.created_at

        dict_payload = _payload.dict()

        self.__cached_dict_payload = dict_payload

        return dict_payload


async def create_user(payload: schemas.CreateUserSchema, request: Request, background_tasks: BackgroundTasks) -> ORJSONResponse:
    """
    Insert new user; verify user email

    :raises HTTPException: when are an error sending the verification email [HTTP_500_INTERNAL_SERVER_ERROR]
    """
    user = User.find_one({'email': payload.email.lower()})

    auth_utils = UserAuthUtils(user, payload)

    new_user_data: dict = (auth_utils
                           .user_does_not_exist_yet()
                           .password_and_password_confirmation_are_the_same()
                           .user_payload)

    result = User.insert_one(new_user_data)
    new_user = user_response_entity(User.find_one({'_id': result.inserted_id}))

    try:
        EmailAuthUtils(request, background_tasks, payload).send_verification_code(
            result.inserted_id, new_user)
    except EmailAuthUtils.NotSent:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail='There was an error sending email')

    return ORJSONResponse(
        content={
            "status": "success", "message": "Verification token successfully sent to your email",
            "user": new_user
        },
        status_code=status.HTTP_201_CREATED
    )


async def login(payload: schemas.LoginUserSchema,
                response: Response,
                Authorize: AuthJWT = Depends()) -> dict:

    user = user_entity(User.find_one({'email': payload.email.lower()}))
    (UserAuthUtils(user, payload)
        .user_exist()
        .is_email_verified()
        .is_password_valid()
     )

    access_token = Authorize.create_access_token(
        subject=str(user["id"]),
        expires_time=timedelta(days=ACCESS_TOKEN_EXPIRES_IN))

    refresh_token = Authorize.create_refresh_token(
        subject=str(user["id"]),
        expires_time=timedelta(days=REFRESH_TOKEN_EXPIRES_IN))

    # Store refresh and access tokens in cookie
    response.set_cookie('access_token', access_token,
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN), '/',
                        None, False, True, 'lax')
    response.set_cookie('refresh_token', refresh_token,
                        __get_days_to_secods(REFRESH_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(REFRESH_TOKEN_EXPIRES_IN), '/',
                        None, False, True, 'lax')
    response.set_cookie('logged_in', 'True',
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN), '/',
                        None, False, False, 'lax')

    return {'status': 'success', 'access_token': access_token}


async def refresh_token(response: Response, Authorize: AuthJWT = Depends()) -> dict:
    """
    :raises HTTPException: when jwt subject do not exist [HTTP_401_UNAUTHORIZED]
    :raises HTTPException: when user no longer exist [HTTP_401_UNAUTHORIZED]
    :raises HTTPException: when refresh toke was not provided
    """

    try:
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')

        user = user_entity(User.find_one({'_id': ObjectId(str(user_id))}))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='The user belonging to this token no logger exist')

        access_token = Authorize.create_access_token(
            subject=str(user["id"]),
            expires_time=timedelta(days=ACCESS_TOKEN_EXPIRES_IN)
        )

    except Exception as e:
        pprint(e)
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Please provide refresh token')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=error)

    response.set_cookie('access_token', access_token,
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(
                            ACCESS_TOKEN_EXPIRES_IN), '/', None, False, True,
                        'lax')
    response.set_cookie('logged_in', 'True', __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(
                            ACCESS_TOKEN_EXPIRES_IN), '/', None, False, False,
                        'lax')

    return {'access_token': access_token}


async def logout(
    response: Response,
    Authorize: AuthJWT = Depends(),
    user_id: str = Depends(oauth2.require_user)
) -> ORJSONResponse:

    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return ORJSONResponse(content={'status': 'success'}, status_code=status.HTTP_200_OK)


async def verify_email(token: str) -> ORJSONResponse:
    verification_code = EmailAuthUtils.get_verification_code_from_token(token)
    result = EmailAuthUtils.verify_user_by_verification_code(verification_code)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Invalid verification code or account already verified')

    return ORJSONResponse(content={
        "status": "success",
        "message": "Account verified successfully"
    })
