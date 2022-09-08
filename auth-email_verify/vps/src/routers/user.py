from fastapi import APIRouter, FastAPI
from ..model import schemas
from ..controllers import user


def init(app: FastAPI) -> APIRouter:
    """
    Add users router to fast api(v1) instance

    :param app: the main fast api instance
    :type app: `FastAPI`

    :returns: The user routes
    :rtype: `APIRouter`
    """

    users_router = APIRouter()

    users_router.add_api_route(
        path="/self",
        endpoint=user.get_current_user,
        summary="Get details of currently logged in user",
        methods=["GET"],
        response_model=schemas.UserResponse)

    users_router.add_api_route("/{user_id}",
                               user.get_user,
                               summary="Get user by id",
                               methods=["GET"],
                               response_model=schemas.UserResponse)

    users_router.add_api_route("/{user_id}",
                               user.update_user,
                               summary="Update user by id",
                               methods=["PUT"],
                               response_model=schemas.UserResponse)

    users_router.add_api_route("/{user_id}",
                               user.delete_user,
                               summary="Delete user by id",
                               methods=["DELETE"],
                               response_model=schemas.UserResponse)

    app.include_router(users_router, tags=['Users'], prefix='/api/v1/users')
    return users_router