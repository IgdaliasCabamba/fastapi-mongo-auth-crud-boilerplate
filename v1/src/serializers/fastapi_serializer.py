from typing import Any, Type


class Field:
    def __init__(self, name: str = None, filed_type: Type = None) -> None:
        self.__name = name
        self.__filed_type = filed_type

    @property
    def name(self) -> str:
        return self.__name

    def get(self, obj: Any):
        if callable(self.__filed_type):
            return self.__filed_type(obj)
        return obj


class CharField(Field):
    def __init__(self, name: str = None) -> None:
        super().__init__(name, str)


class IntegerField(Field):
    def __init__(self, name: str = None) -> None:
        super().__init__(name, int)


class FloatField(Field):
    def __init__(self, name: str = None) -> None:
        super().__init__(name, float)


class BooleanField(Field):
    def __init__(self, name: str = None) -> None:
        super().__init__(name, bool)


class SerializerMetaClass(type):

    @classmethod
    def _get_declared_fields(cls, bases, attrs) -> list:
        fields = dict()

        for field_name, obj in list(attrs.items()):
            if isinstance(obj, Field):
                fields[field_name] = obj
                attrs.pop(field_name)

        base_fields: dict = {}

        for base in bases:
            if hasattr(base, '_declared_fields'):
                base_fields.update(base._declared_fields)

        return {**base_fields, **fields}

    def __new__(cls, clsname, bases, attrs):
        attrs["_declared_fields"] = cls._get_declared_fields(bases, attrs)
        return super().__new__(cls, clsname, bases, attrs)


class BaseSerializer:
    def __init__(self, *args, **kwargs):
        if args:
            self.__object_to_serialize = args[0]
        if kwargs:
            self.__init_kwargs = kwargs

    @property
    def object_to_serialize(self) -> Any:
        return self.__object_to_serialize


class Serializer(BaseSerializer, metaclass=SerializerMetaClass):

    class _NullField:
        ...

    @property
    def declared_fields(self) -> dict:
        return self._declared_fields


class JsonSerializer(Serializer):

    @property
    def data(self):
        dict_response = dict()
        if isinstance(self.object_to_serialize, dict):
            for attr_name, field in self.declared_fields.items():
                if field.name is not None:

                    raw_value_to_serialize = self.object_to_serialize.get(
                        field.name, Serializer._NullField)
                else:
                    raw_value_to_serialize = self.object_to_serialize.get(
                        attr_name, Serializer._NullField)

                if raw_value_to_serialize is not Serializer._NullField:
                    dict_response[attr_name] = field.get(
                        raw_value_to_serialize)
        return dict_response


class ModelSerializer(Serializer):
    ...
