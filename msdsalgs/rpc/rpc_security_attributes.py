from __future__ import annotations
from dataclasses import dataclass
from typing import ByteString
from struct import pack, unpack_from

from msdsalgs.rpc.rpc_security_descriptor import RPCSecurityDescriptor


@dataclass
class RPCSecurityAttributes:
    rpc_security_descriptor: RPCSecurityDescriptor
    inherit_handle: bool

    @classmethod
    def from_bytes(cls, data: ByteString, base_offset: int = 0) -> RPCSecurityAttributes:
        data = memoryview(data)[base_offset:]
        offset = 0

        security_descriptor_len = unpack_from('<I', buffer=data, offset=offset)
        offset += 4

        rpc_security_descriptor = RPCSecurityDescriptor.from_bytes(data=data, base_offset=offset)
        offset += len(rpc_security_descriptor)

        return cls(
            rpc_security_descriptor=rpc_security_descriptor,
            inherit_handle=bool(bytes(data[offset]))
        )

    def __bytes__(self) -> bytes:
        rpc_security_descriptor_bytes = bytes(self.rpc_security_descriptor)
        security_descriptor_len = self.rpc_security_descriptor.in_security_descriptor

        return b''.join([
            pack('<I', security_descriptor_len),
            rpc_security_descriptor_bytes,
            pack('<B', int(self.inherit_handle))
        ])

    def __len__(self) -> int:
        return 4 + len(self.rpc_security_descriptor) + 1

