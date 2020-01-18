from __future__ import annotations
from dataclasses import dataclass

from msdsalgs.rpc.rpc_security_descriptor import RPCSecurityDescriptor


@dataclass
class RPCSecurityAttributes:
    rpc_security_descriptor: RPCSecurityDescriptor
    inherit_handle: bool

    @classmethod
    def from_bytes(cls, data: bytes) -> RPCSecurityAttributes:
        rpc_security_descriptor = RPCSecurityDescriptor.from_bytes(data=data)
        return cls(
            rpc_security_descriptor=rpc_security_descriptor,
            inherit_handle=bool(data[len(rpc_security_descriptor)])
        )
