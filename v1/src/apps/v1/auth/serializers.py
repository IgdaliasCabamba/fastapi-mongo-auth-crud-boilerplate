from src.serializers import fastapi_serializer

class BaseUserEntitySerializer(fastapi_serializer.JsonSerializer):
    id = fastapi_serializer.CharField("_id")
    name = fastapi_serializer.CharField()
    email = fastapi_serializer.CharField()
    photo = fastapi_serializer.CharField()

class UserEntitySerializer(BaseUserEntitySerializer):
    role = fastapi_serializer.Field()
    verified = fastapi_serializer.BooleanField()
    password = fastapi_serializer.CharField()
    created_at = fastapi_serializer.Field()
    updated_at = fastapi_serializer.Field()

class UserResponseEntitySerializer(BaseUserEntitySerializer):
    role = fastapi_serializer.Field()
    created_at = fastapi_serializer.Field()
    updated_at = fastapi_serializer.Field()

def user_entity(user) -> dict:
    return UserEntitySerializer(user).data

def user_response_entity(user) -> dict:
    return UserResponseEntitySerializer(user).data

def user_list_entity(users) -> list:
    return [user_entity(user) for user in users]