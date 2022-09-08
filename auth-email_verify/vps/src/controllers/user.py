import pprint
from fastapi import Depends
from bson.objectid import ObjectId
from src.serializers.user_serializers import userResponseEntity
from ..utils import oauth2
from ..model.database import User


async def get_user(user_id: str) -> dict:
    query = {'_id': ObjectId(str(user_id))}
    filter = {"_id": 0}
    user = userResponseEntity(User.find_one(query, filter))
    pprint.pprint(user)
    return {"status": True, "data": {"user": user}}


async def get_current_user(user_id: str = Depends(
    oauth2.require_user)) -> dict:
    print(user_id)
    pprint.pprint(User.find_one({'_id': ObjectId(str(user_id))}))
    query = {'_id': ObjectId(str(user_id))}
    filter = {"_id": 0}
    user = userResponseEntity(User.find_one(query, filter))
    return {"status": True, "data": {"user": user}}


async def delete_user(user_id: str = Depends(oauth2.require_user)) -> dict:
    query = {'_id': ObjectId(str(user_id))}
    filter = {"_id": 0}
    deleted_user = userResponseEntity(User.find_one_and_delete(query, filter))
    pprint.pprint(deleted_user)
    return {"status": True, "data": {"user": deleted_user}}


async def update_user(user_id: str = Depends(oauth2.require_user)) -> dict:
    ...
    update_user = {"foo":"bar"}
    return {"status": True, "data": {"user": update_user}}
