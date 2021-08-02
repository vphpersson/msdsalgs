from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar, ByteString, Optional
from struct import pack

from ndr.structures.pointer import Pointer, NullPointer

from msdsalgs.security_types.security_descriptor import SecurityDescriptor


@dataclass
class RPCSecurityDescriptor:
    # TODO: Is this correct?
    STRUCTURE_SIZE: ClassVar[int] = 8

    security_descriptor: Optional[SecurityDescriptor] = None

    @property
    def in_security_descriptor(self) -> int:
        return len(bytes(self.security_descriptor)) if self.security_descriptor is not None else 0

    @property
    def out_security_descriptor(self) -> int:
        return len(bytes(self.security_descriptor)) if self.security_descriptor is not None else 0

    @classmethod
    def from_bytes(cls, data: ByteString, base_offset: int = 0) -> RPCSecurityDescriptor:
        data = memoryview(data)[base_offset:]
        offset = 0

        security_descriptor_pointer = Pointer.from_bytes(data=data, base_offset=offset)
        security_descriptor = SecurityDescriptor.from_bytes(
            data=security_descriptor_pointer.representation
        ) if not isinstance(security_descriptor_pointer, NullPointer) else None

        # TODO: Parse `cbInSecurityDescriptor` and `cbOutSecurityDescriptor`?

        return cls(security_descriptor=security_descriptor)

    def __bytes__(self) -> bytes:
        security_descriptor_len = self.in_security_descriptor

        return b''.join([
            bytes(
                Pointer(representation=bytes(self.security_descriptor)) if self.security_descriptor is not None
                else NullPointer()
            ),
            pack('<H', security_descriptor_len),
            pack('<H', security_descriptor_len)
        ])

    def __len__(self) -> int:
        return Pointer.structure_size + self.in_security_descriptor + 4 + 4
