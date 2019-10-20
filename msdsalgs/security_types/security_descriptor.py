from enum import IntFlag
from dataclasses import dataclass
from struct import unpack as struct_unpack
from typing import Optional, ClassVar

from ad_data_gatherer.utils.microsoft_structures.sid import SID
from ad_data_gatherer.utils.microsoft_structures.acl import SACL, DACL


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
    SE_DACL_AUTO_INHERIT_REQ = 0x0100,
    SE_DACL_AUTO_INHERITED = 0x0400,
    SE_DACL_DEFAULTED = 0x0008,
    SE_DACL_PRESENT = 0x0004,
    SE_DACL_PROTECTED = 0x1000,
    SE_GROUP_DEFAULTED = 0x0002,
    SE_OWNER_DEFAULTED = 0x0001,
    SE_RM_CONTROL_VALID = 0x4000,
    SE_SACL_AUTO_INHERIT_REQ = 0x0200,
    SE_SACL_AUTO_INHERITED = 0x0800,
    SE_SACL_DEFAULTED = 0x0008,
    SE_SACL_PRESENT = 0x0010,
    SE_SACL_PROTECTED = 0x2000,
    SE_SELF_RELATIVE = 0x8000


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

    revision: ClassVar[int] = 0x1
    _sbz1: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'SecurityDescriptor':
        control_mask = SecurityDescriptorControlMask(struct_unpack('<H', data[2:4])[0])
        owner_offset: int = struct_unpack('<L', data[4:8])[0]
        group_offset: int = struct_unpack('<L', data[8:12])[0]
        sacl_offset: int = struct_unpack('<L', data[12:16])[0]
        dacl_offset: int = struct_unpack('<L', data[16:20])[0]

        if owner_offset == 0 and not control_mask.SE_OWNER_DEFAULTED:
            raise BadOwnerOffsetError(
                offset=owner_offset,
                msg='The owner offset is 0 even though `SE_OWNER_DEFAULTED` is not set.'
            )

        if group_offset == 0 and not control_mask.SE_GROUP_DEFAULTED:
            raise BadGroupOffsetError(
                offset=group_offset,
                msg='The group offset is 0 even though `SE_GROUP_DEFAULTED` is not set.'
            )

        if sacl_offset == 0 and control_mask.SE_SACL_PRESENT:
            raise BadSACLOffsetError(
                offset=sacl_offset,
                msg='The SACL offset is 0 even though `SE_SACL_PRESENT` is set.'
            )

        if dacl_offset == 0 and control_mask.SE_DACL_PRESENT:
            raise BadSACLOffsetError(
                offset=dacl_offset,
                msg='The DACL offset is 0 even though `SE_DACL_PRESENT` is set.'
            )

        return cls(
            _sbz1=struct_unpack('<B', data[1:2])[0],
            control=control_mask,
            owner_sid=SID.from_bytes(data[owner_offset:group_offset]) if owner_offset != 0 else None,
            group_sid=SID.from_bytes(data[group_offset:]) if group_offset != 0 else None,
            dacl=DACL.from_bytes(data=data[dacl_offset:]) if dacl_offset != 0 else None,
            sacl=SACL.from_bytes(data=data[sacl_offset:]) if sacl_offset != 0 else None
        )
