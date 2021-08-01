from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from struct import pack

from msdsalgs.rpc.rpc_security_descriptor import RPCSecurityDescriptor


@dataclass
class RPCSecurityAttributes:
    rpc_security_descriptor: Optional[RPCSecurityDescriptor] = None
    inherit_handle: bool = False

    @classmethod
    def from_bytes(cls, data: bytes) -> RPCSecurityAttributes:
        rpc_security_descriptor = RPCSecurityDescriptor.from_bytes(data=data)
        return cls(
            rpc_security_descriptor=rpc_security_descriptor,
            inherit_handle=bool(data[len(rpc_security_descriptor)])
        )

    def __bytes__(self) -> bytes:

        # TODO: Not sure why `bytes(12)`; it is something I observed in traffic. I think there is an NDR Pointer
        #   involved.
        security_description_bytes: bytes = (
            bytes(self.rpc_security_descriptor) if self.rpc_security_descriptor is not None
            else bytes(12)
        )

        security_description_len: int = (
            len(security_description_bytes) if self.rpc_security_descriptor is not None else 0
        )

        return b''.join([
            pack('<I', security_description_len),
            security_description_bytes,
            pack('<I', int(self.inherit_handle))
        ])
