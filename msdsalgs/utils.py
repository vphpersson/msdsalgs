from __future__ import annotations
from typing import Type, Optional, Callable, Any, List, Dict, Final, Tuple
from inspect import getmembers
from enum import IntFlag
from re import sub as re_sub
from abc import ABC

from pyutils.my_string import to_snake_case


class Mask(ABC):
    INT_FLAG_CLASS: Final[Type[IntFlag]] = NotImplemented

    def __init__(self):
        self._mask: IntFlag = self.INT_FLAG_CLASS(0)

    @classmethod
    def from_int(cls, value: int):
        cls_instance = cls()
        cls_instance._mask |= value
        return cls_instance

    def to_int_flag(self) -> IntFlag:
        return self.INT_FLAG_CLASS(self._mask.value)

    def set_all(self) -> None:
        for key, _ in self.items():
            setattr(self, key, True)

    def clear_all(self) -> None:
        for key, _ in self.items():
            setattr(self, key, False)

    def items(self) -> Tuple[Tuple[str, bool], ...]:
        return tuple(
            (name, value)
            for name, value in getmembers(self, lambda value: not callable(value))
            if not name.startswith('_')
        )

    def __repr__(self) -> str:
        return repr(self._mask)

    def __eq__(self, other: Mask) -> bool:
        return self.to_int_flag() == other.to_int_flag()

    def __int__(self) -> int:
        return self._mask.value

    @classmethod
    def make_class(
        cls,
        int_flag_class: Type[IntFlag],
        name: Optional[str] = None,
        prefix: str = '',
        attribute_name_formatter: Optional[Callable[[str], str]] = None
    ) -> Type[Mask]:
        """
        Dynamically create a new `Mask` child class from an `IntFlag` class.

        :param int_flag_class: An `IntFlag` class with enumeration members to be added to the class to be created.
        :param name: The name of the class to be created.
        :param prefix: A prefix of the enumeration member attributes in `int_flag_class` that is to be ignored.
        :param attribute_name_formatter: A function that will format the attribute names.
        :return: A mask class with attributes corresponding to those in the provided `IntFlag` class.
        """

        mask_class = type(
            name or re_sub(r'(Flag|Mask)+$', '', int_flag_class.__name__),
            (cls,),
            dict()
        )

        attribute_name_formatter: Callable[[str], str] = attribute_name_formatter or to_snake_case

        def make_field_property_accessor(enum_member: IntFlag):
            def field_getter(self) -> bool:
                return enum_member in self._mask

            def field_setter(self, value: bool) -> None:
                if value:
                    self._mask |= enum_member
                else:
                    self._mask &= ~enum_member

            return property(field_getter, field_setter)

        attribute_name_to_false: Dict[str, bool] = {}
        for enum_member in int_flag_class:
            attribute_name: str = attribute_name_formatter(
                re_sub(pattern=f'^{prefix}', repl='', string=enum_member.name)
            )
            setattr(mask_class, attribute_name, make_field_property_accessor(enum_member=enum_member))
            attribute_name_to_false[attribute_name] = False

        def constructor(self, **kwargs):
            super(mask_class, self).__init__()
            for attribute_name, value in {**attribute_name_to_false, **kwargs}.items():
                if attribute_name not in attribute_name_to_false:
                    raise ValueError(f'{attribute_name} is not part of the mask.')
                setattr(self, attribute_name, value)

        setattr(mask_class, '__init__', constructor)
        setattr(mask_class, 'INT_FLAG_CLASS', int_flag_class)

        return mask_class


def extract_elements(
    data: bytes,
    create_element: Callable[[bytes], Any],
    get_next_offset: Callable[[Any], int]
) -> List[Any]:

    if not data:
        return []

    elements: List[Any] = []

    while True:
        element: Any = create_element(data)
        elements.append(element)

        # TODO: Maybe this should return `None` if there is no offset! Consequently: `if next_offset is None`.
        next_offset: int = get_next_offset(element)

        if next_offset == 0:
            break

        data = data[next_offset:]

    return elements
