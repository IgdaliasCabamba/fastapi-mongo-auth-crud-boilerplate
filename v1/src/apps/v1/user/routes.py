from fastapi import APIRouter
from . import controller, schemas

users_router = APIRouter()

users_router.add_api_route(
    path="/",
    endpoint=controller.get_current_user,
    summary="Get details of currently logged in user",
    methods=["GET"],
    response_model=schemas.UserResponse)

users_router.add_api_route("/",
                        controller.update_user,
                        summary="Update user",
                        methods=["PUT"],
                        response_model=schemas.UserResponse)

users_router.add_api_route("/",
                        controller.delete_user,
                        summary="Delete user",
                        methods=["DELETE"],
                        response_model=schemas.UserResponse)
