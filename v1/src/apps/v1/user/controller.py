import pprint
from fastapi import Depends, status
from bson.objectid import ObjectId
from fastapi.responses import ORJSONResponse
from .user_serializers import user_response_entity
from src.utils import oauth2
from src.utils.database import User


async def get_current_user(user_id: str = Depends(
        oauth2.require_user)) -> ORJSONResponse:
    print(user_id)
    pprint.pprint(User.find_one({'_id': ObjectId(str(user_id))}))
    query = {'_id': ObjectId(str(user_id))}
    filter = {"_id": 0}
    user = user_response_entity(User.find_one(query, filter))
    return ORJSONResponse(content={"status": True, "data": {"user": user}})


async def delete_user(user_id: str = Depends(oauth2.require_user)) -> ORJSONResponse:
    query = {'_id': ObjectId(str(user_id))}
    filter = {"_id": 0}
    deleted_user = user_response_entity(
        User.find_one_and_delete(query, filter))
    pprint.pprint(deleted_user)
    return ORJSONResponse(content={"status": True, "data": {"user": deleted_user}})


async def update_user(user_id: str = Depends(oauth2.require_user)) -> ORJSONResponse:
    ...
    update_user = {"foo": "bar"}
    return ORJSONResponse(content={"status": True, "data": {"user": update_user}})
