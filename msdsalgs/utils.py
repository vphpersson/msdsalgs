from typing import Type, Optional, Callable, Any, List, Dict
from enum import IntFlag
from re import compile as re_compile, sub as re_sub


def make_mask_class(int_flag_enum_cls: Type[IntFlag], name: Optional[str] = None, prefix: str = ''):

    mask = int_flag_enum_cls(0x00)

    # TODO: The name generation is curious.
    int_flag_cls = type(
        name or re_sub(r'^(Flag|Mask)$', '', int_flag_enum_cls.__name__),
        (object,),
        dict(_mask=mask)
    )

    prefix_pattern = re_compile('^' + prefix.lower())
    field_name_to_false: Dict[str, bool] = {}

    def make_field_property_accessor(enum_entry: IntFlag):
        def field_getter(self) -> bool:
            return enum_entry in self._mask

        def field_setter(self, value: bool) -> None:
            if value:
                self._mask |= enum_entry
            else:
                self._mask &= ~enum_entry

        return property(field_getter, field_setter)

    for enum_entry in int_flag_enum_cls:
        field_name = prefix_pattern.sub(repl='', string=enum_entry.name.lower())
        field_name_to_false[field_name] = False

        setattr(int_flag_cls, field_name, make_field_property_accessor(enum_entry))

    def constructor(self, **kwargs):
        for field_name, value in {**field_name_to_false, **kwargs}.items():
            if field_name not in field_name_to_false:
                raise ValueError(f'{field_name} is not part of the mask.')
            setattr(self, field_name, value)

    @classmethod
    def from_int(cls, value: int):
        cls_instance = cls()
        cls_instance._mask |= value
        return cls_instance

    def to_int_flag(self) -> IntFlag:
        return int_flag_enum_cls(self._mask.value)

    def set_all(self) -> None:
        for field_name in field_name_to_false:
            setattr(self, field_name, True)

    def clear_all(self) -> None:
        for field_name in field_name_to_false:
            setattr(self, field_name, False)

    def __repr__(self) -> str:
        return repr(self._mask)

    def __eq__(self, other) -> bool:
        return self.to_mask() == other.to_mask()

    def __int__(self) -> int:
        return self._mask.value

    setattr(int_flag_cls, '__init__', constructor)
    setattr(int_flag_cls, 'from_int', from_int)
    setattr(int_flag_cls, 'to_int_flag', to_int_flag)
    setattr(int_flag_cls, 'set_all', set_all)
    setattr(int_flag_cls, 'clear_all', clear_all)
    setattr(int_flag_cls, '__repr__', __repr__)
    setattr(int_flag_cls, '__eq__', __eq__)
    setattr(int_flag_cls, '__int__', __int__)

    return int_flag_cls


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
