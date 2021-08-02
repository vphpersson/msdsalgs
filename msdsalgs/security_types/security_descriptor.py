from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, ClassVar, ByteString
from enum import IntFlag
from struct import unpack_from, pack

from msdsalgs.security_types.sid import SID
from msdsalgs.security_types.acl import SACL, DACL

from msdsalgs.utils import Mask


class BadSecurityDescriptorOffsetError(Exception):
    def __init__(self, offset: int, msg: Optional[str] = None):
        super().__init__(msg or f'Bad offset: {offset}.')
        self.offset = offset


class BadOwnerOffsetError(BadSecurityDescriptorOffsetError):
    pass


class BadGroupOffsetError(BadSecurityDescriptorOffsetError):
    pass


class BadDACLOffsetError(BadSecurityDescriptorOffsetError):
    pass


class BadSACLOffsetError(BadSecurityDescriptorOffsetError):
    pass


class SecurityDescriptorControlMask(IntFlag):
    SE_DACL_AUTO_INHERIT_REQ = 0x0100
    SE_DACL_AUTO_INHERITED = 0x0400
    SE_DACL_DEFAULTED = 0x0008
    SE_DACL_PRESENT = 0x0004
    SE_DACL_PROTECTED = 0x1000
    SE_GROUP_DEFAULTED = 0x0002
    SE_OWNER_DEFAULTED = 0x0001
    SE_RM_CONTROL_VALID = 0x4000
    SE_SACL_AUTO_INHERIT_REQ = 0x0200
    SE_SACL_AUTO_INHERITED = 0x0800
    SE_SACL_DEFAULTED = 0x0008
    SE_SACL_PRESENT = 0x0010
    SE_SACL_PROTECTED = 0x2000
    SE_SELF_RELATIVE = 0x8000


SecurityDescriptorControl = Mask.make_class(
    int_flag_class=SecurityDescriptorControlMask,
    prefix='SE_'
)


@dataclass
class SecurityDescriptor:
    """
    [MS-DTYP]: SECURITY_DESCRIPTOR | Microsoft Docs

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
    """

    control: SecurityDescriptorControlMask
    owner_sid: Optional[SID]
    group_sid: Optional[SID]
    sacl: Optional[SACL]
    dacl: Optional[DACL]

    REVISION: ClassVar[int] = 1
    SBZ_1: ClassVar[int] = 1

    @classmethod
    def from_bytes(cls, data: ByteString, base_offset: int = 0) -> SecurityDescriptor:
        data = memoryview(data)[base_offset:]
        offset = 0

        # TODO: Parse `Revision` and `Sbz1`?
        offset += 2

        control_mask = SecurityDescriptorControl.from_int(value=unpack_from('<H', buffer=data, offset=offset)[0])
        offset += 2

        owner_offset: int = unpack_from('<I', buffer=data, offset=offset)[0]
        offset += 4

        group_offset: int = unpack_from('<I', buffer=data, offset=offset)[0]
        offset += 4

        sacl_offset: int = unpack_from('<I', buffer=data, offset=offset)[0]
        offset += 4

        dacl_offset: int = unpack_from('<I', buffer=data, offset=offset)[0]
        offset += 4

        if owner_offset == 0 and not control_mask.owner_defaulted:
            raise BadOwnerOffsetError(
                offset=owner_offset,
                msg='The owner offset is 0 even though `SE_OWNER_DEFAULTED` is not set.'
            )

        if group_offset == 0 and not control_mask.group_defaulted:
            raise BadGroupOffsetError(
                offset=group_offset,
                msg='The group offset is 0 even though `SE_GROUP_DEFAULTED` is not set.'
            )

        if sacl_offset == 0 and control_mask.sacl_present:
            raise BadSACLOffsetError(
                offset=sacl_offset,
                msg='The SACL offset is 0 even though `SE_SACL_PRESENT` is set.'
            )

        if dacl_offset == 0 and control_mask.dacl_present:
            raise BadSACLOffsetError(
                offset=dacl_offset,
                msg='The DACL offset is 0 even though `SE_DACL_PRESENT` is set.'
            )

        return cls(
            control=control_mask,
            owner_sid=SID.from_bytes(data=data[owner_offset:group_offset]) if owner_offset != 0 else None,
            group_sid=SID.from_bytes(data=data[group_offset:]) if group_offset != 0 else None,
            dacl=DACL.from_bytes(data=data[dacl_offset:]) if dacl_offset != 0 else None,
            sacl=SACL.from_bytes(data=data[sacl_offset:]) if sacl_offset != 0 else None
        )

    def __bytes__(self) -> bytes:

        structures_offset = 20

        if self.owner_sid is not None:
            owner_sid_offset = structures_offset
            structures_offset += len(self.owner_sid)
        else:
            owner_sid_offset = 0

        if self.group_sid is not None:
            group_sid_offset = structures_offset
            structures_offset += len(self.group_sid)
        else:
            group_sid_offset = 0

        if self.sacl is not None:
            sacl_offset = structures_offset
            structures_offset += len(self.sacl)
        else:
            sacl_offset = 0

        if self.dacl is not None:
            dacl_offset = structures_offset
            structures_offset += len(self.dacl)
        else:
            dacl_offset = 0

        return b''.join([
            self.REVISION,
            self.SBZ_1,
            pack('<H', int(self.control)),
            pack('<I', owner_sid_offset),
            pack('<I', group_sid_offset),
            pack('<I', sacl_offset),
            pack('<I', dacl_offset)
        ])
