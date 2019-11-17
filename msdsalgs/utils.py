from typing import Type, Optional, Union, Callable, Any, List
from enum import IntFlag
from re import compile as re_compile, sub as re_sub


def make_mask_class(int_flag_enum_cls: Type[IntFlag], name: Optional[str] = None, prefix: str = ''):

    mask = int_flag_enum_cls(0x00)

    int_flag_cls = type(
        name or re_sub(r'^(Flag|Mask)$', '', int_flag_enum_cls.__name__),
        (object,),
        dict(_mask=mask)
    )

    prefix_pattern = re_compile('^' + prefix.lower())
    field_name_to_false = {}

    def make_field_property_accessor(enum_entry: IntFlag):
        def field_getter(self) -> bool:
            return enum_entry in self._mask

        def field_setter(self, value: bool) -> None:
            if not isinstance(value, bool):
                raise ValueError('Flag assign value must be a boolean.')

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
        c = {**field_name_to_false, **kwargs}
        for field_name, value in c.items():
            setattr(self, field_name, value)

    @classmethod
    def from_mask(cls, mask: Union[IntFlag, int]):
        cls_instance = cls()

        if isinstance(mask, IntFlag):
            cls_instance._mask |= mask.value
        elif isinstance(mask, int):
            cls_instance._mask |= mask
        else:
            # TODO: Add a proper exception.
            raise ValueError('bad mask format')

        return cls_instance

    def to_mask(self) -> IntFlag:
        return int_flag_enum_cls(self._mask.value)

    def set_all(self) -> None:
        for field_name in field_name_to_false:
            setattr(self, field_name, True)

    setattr(int_flag_cls, '__init__', constructor)
    setattr(int_flag_cls, 'from_mask', from_mask)
    setattr(int_flag_cls, 'to_mask', to_mask)
    setattr(int_flag_cls, 'set_all', set_all)

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
