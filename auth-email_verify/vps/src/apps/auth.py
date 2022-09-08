"""
Authentication App for fastapi, 
it's an internal service that provide authentication and login utilities

:example:
>>> from .apps import auth
>>> app.mount(path='/api/v1/auth', app=auth.auth_app, name='Auth')
"""
from datetime import datetime, timedelta
import hashlib
import secrets
from bson.objectid import ObjectId
from fastapi import FastAPI, Response, Request, status, Depends, HTTPException
from pydantic import EmailStr

from src.utils import oauth2, security, email
from src.model.database import User
from src.serializers.user_serializers import userEntity, userResponseEntity
from src.model import schemas
from src.utils.oauth2 import AuthJWT
from src.utils.config import settings

auth_app = FastAPI()
ACCESS_TOKEN_EXPIRES_IN = settings.ACCESS_TOKEN_EXPIRES_IN
REFRESH_TOKEN_EXPIRES_IN = settings.REFRESH_TOKEN_EXPIRES_IN


def __get_days_to_secods(days: int) -> int:
    """
    Compute the seconds from the `days`

    :param days: the amount of days
    :type days: int
    :rtype int: the seconds
    """
    if isinstance(days, int):
        return days * 60 * 24
    return 1 * 60 * 24  # 1 day


@auth_app.post('/signup', status_code=status.HTTP_201_CREATED)
async def create_user(payload: schemas.CreateUserSchema, request: Request) -> dict:
    """
    Create a new user(document) if it's doesnt exist on db
    
    :param payload: the request body
    :type payload: CreateUserSchema
    :raise HTTPException: when the user already exist(HTTP_409_CONFLICT)
    :raise HTTPException: when passwords do not match(HTTP_400_BAD_REQUEST)
    """
    user = User.find_one({'email': payload.email.lower()})

    def user_exist() -> None:
        """Check if user already exist"""
        if user:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                                detail='Account already exist')

    def verify_password_and_password_confirm() -> None:
        """Compare password and passwordConfirm"""
        if payload.password != payload.passwordConfirm:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Passwords do not match')

    def make_user() -> dict:
        """
        Create new user and prepare to insert on db
        
        :example:
            >>> new_user_data = make_user()
            >>> result = User.insert_one(`new_user_data`)
            ...

        :rtype: dict
        """
        #  Hash the password
        payload.password = security.hash_password(payload.password)

        #  Remove useless data
        del payload.passwordConfirm

        payload.role = 'user'
        payload.verified = False
        payload.email = payload.email.lower()
        payload.created_at = datetime.utcnow()
        payload.updated_at = payload.created_at

        return payload.dict()

    user_exist()
    verify_password_and_password_confirm()
    new_user_data: dict = make_user()

    result = User.insert_one(new_user_data)
    new_user = userResponseEntity(User.find_one({'_id': result.inserted_id}))
    
    try:
        token = secrets.token_bytes(10)
        hashedCode = hashlib.sha256()
        hashedCode.update(token)
        verification_code = hashedCode.hexdigest()
        User.find_one_and_update({"_id": result.inserted_id}, {
            "$set": {"verification_code": verification_code, "updated_at": datetime.utcnow()}})

        url = f"{request.url.scheme}://{request.client.host}:{request.url.port}/api/v1/auth/verifyemail/{token.hex()}"
        await email.Email(new_user, url, [EmailStr(payload.email)]).sendVerificationCode()

    except Exception as error:
        User.find_one_and_update({"_id": result.inserted_id}, {
            "$set": {"verification_code": None, "updated_at": datetime.utcnow()}})
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail='There was an error sending email')

    return {"status": "success", "message": "Verification token successfully sent to your email", "user": new_user}


@auth_app.post('/login')
def login(payload: schemas.LoginUserSchema,
          response: Response,
          Authorize: AuthJWT = Depends()) -> dict:
    """
    Create acess and refresh tokens
    
    :param payload: the request body
    :type payload: LoginUserSchema
    :raises HTTPException: when email or password is wrong(HTTP_400_BAD_REQUEST)
    :raises HTTPException: when user still did not verified his email(HTTP_401_UNAUTHORIZED)
    :raises HTTPException: when password is not valid(HTTP_400_BAD_REQUEST)
    :rtype dict: the response
    """
    user = userEntity(User.find_one({'email': payload.email.lower()}))

    def user_exist() -> None:
        """Check if the user exist"""
        if not user:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Incorrect Email or Password')

    def is_email_verified() -> None:
        """Check if user verified his email"""
        if not user['verified']:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Please verify your email address')

    def is_password_valid() -> None:
        """Check if the password is valid"""
        if not security.verify_password(payload.password, user['password']):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Incorrect Email or Password')

    user_exist()
    is_email_verified()
    is_password_valid()

    # Create access token
    access_token = Authorize.create_access_token(
        subject=str(user["id"]),
        expires_time=timedelta(days=ACCESS_TOKEN_EXPIRES_IN))

    # Create refresh token
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

    # Send both access
    return {'status': 'success', 'access_token': access_token}


@auth_app.get('/refresh')
def refresh_token(response: Response, Authorize: AuthJWT = Depends()) -> dict:
    try:
        Authorize.jwt_refresh_token_required()

        user_id = Authorize.get_jwt_subject()
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not refresh access token')
        user = userEntity(User.find_one({'_id': ObjectId(str(user_id))}))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='The user belonging to this token no logger exist')
        access_token = Authorize.create_access_token(
            subject=str(user["id"]),
            expires_time=timedelta(days=ACCESS_TOKEN_EXPIRES_IN))
    except Exception as e:
        error = e.__class__.__name__
        if error == 'MissingTokenError':
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail='Please provide refresh token')
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=error)

    response.set_cookie('access_token', access_token,
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN), '/', None, False, True,
                        'lax')
    response.set_cookie('logged_in', 'True', __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN),
                        __get_days_to_secods(ACCESS_TOKEN_EXPIRES_IN), '/', None, False, False,
                        'lax')
    return {'access_token': access_token}


@auth_app.get('/logout', status_code=status.HTTP_200_OK)
def logout(
    response: Response,
    Authorize: AuthJWT = Depends(),
    user_id: str = Depends(oauth2.require_user)
) -> dict:
    Authorize.unset_jwt_cookies()
    response.set_cookie('logged_in', '', -1)

    return {'status': 'success'}


@auth_app.get('/verifyemail/{token}')
def verify_self(token: str):
    hashedCode = hashlib.sha256()
    hashedCode.update(bytes.fromhex(token))
    verification_code = hashedCode.hexdigest()
    result = User.find_one_and_update({"verification_code": verification_code}, {
        "$set": {"verification_code": None, "verified": True, "updated_at": datetime.utcnow()}}, new=True)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail='Invalid verification code or account already verified')
    return {
        "status": "success",
        "message": "Account verified successfully"
    }