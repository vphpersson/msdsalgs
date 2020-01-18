from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import pack as struct_pack

from msdsalgs.security_types.security_descriptor import SecurityDescriptor


@dataclass
class RPCSecurityDescriptor:
    STRUCTURE_SIZE: ClassVar[int] = 8

    security_descriptor: SecurityDescriptor

    @property
    def in_security_descriptor(self) -> int:
        # TODO: Use `__len__` method once added.
        return len(bytes(self.security_descriptor))

    @property
    def out_security_descriptor(self) -> int:
        return len(bytes(self.security_descriptor))

    @classmethod
    def from_bytes(cls, data: bytes) -> RPCSecurityDescriptor:
        return cls(security_descriptor=SecurityDescriptor.from_bytes(data=data))

    def __bytes__(self) -> bytes:
        return b''.join([
            bytes(self.security_descriptor),
            struct_pack('<H', self.in_security_descriptor),
            struct_pack('<H', self.out_security_descriptor)
        ])

    def __len__(self) -> int:
        return len(self.__bytes__())