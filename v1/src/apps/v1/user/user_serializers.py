from src.serializers import fastapi_serializer

class BaseUserEntitySerializer(fastapi_serializer.JsonSerializer):
    id = fastapi_serializer.CharField("_id")
    name = fastapi_serializer.CharField()
    email = fastapi_serializer.CharField()
    photo = fastapi_serializer.CharField()

class UserResponseEntitySerializer(BaseUserEntitySerializer):
    role = fastapi_serializer.CharField()
    created_at = fastapi_serializer.Field()
    updated_at = fastapi_serializer.Field()


def user_response_entity(user) -> dict:
    return UserResponseEntitySerializer(user).data