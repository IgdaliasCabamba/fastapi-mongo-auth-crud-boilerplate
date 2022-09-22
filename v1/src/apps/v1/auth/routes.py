from fastapi import APIRouter, status
from . import controller

auth_router = APIRouter()

auth_router.add_api_route(path='/signup', endpoint=controller.create_user,
                       status_code=status.HTTP_201_CREATED, methods=["POST"])

auth_router.add_api_route(
    path='/login', endpoint=controller.login, methods=["POST"])

auth_router.add_api_route(
    path='/refresh', endpoint=controller.refresh_token, methods=["GET"])

auth_router.add_api_route(path='/logout', endpoint=controller.logout,
                       status_code=status.HTTP_200_OK, methods=["GET"])

auth_router.add_api_route(
    path='/verifyemail/{token}', endpoint=controller.verify_email, methods=["GET"])
