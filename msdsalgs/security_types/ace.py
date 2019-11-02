from dataclasses import dataclass
from enum import IntFlag, IntEnum
from struct import unpack as struct_unpack, pack as struct_pack
from uuid import UUID
from typing import Optional

from .sid import SID


class ACEType(IntEnum):
    ACCESS_ALLOWED_ACE_TYPE = 0x00,
    ACCESS_DENIED_ACE_TYPE = 0x01,
    SYSTEM_AUDIT_ACE_TYPE = 0x02,
    SYSTEM_ALARM_ACE_TYPE = 0x03,
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05,
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07,
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09,
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C,
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12,
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13


BASIC_ACE_TYPES = {
    ACEType.ACCESS_ALLOWED_ACE_TYPE,
    ACEType.ACCESS_DENIED_ACE_TYPE,
    ACEType.SYSTEM_AUDIT_ACE_TYPE,
    ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
}


OBJECT_ACE_TYPES = {
    ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE,
    ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE
}

DATA_ACE_TYPES = {
    ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE,
    ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
    ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE
}


class ACEFlagsMask(IntFlag):
    CONTAINER_INHERIT_ACE = 0x02,
    FAILED_ACCESS_ACE_FLAG = 0x80,
    INHERIT_ONLY_ACE = 0x08,
    INHERITED_ACE = 0x10,
    NO_PROPAGATE_INHERIT_ACE = 0x04,
    OBJECT_INHERIT_ACE = 0x01,
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40


@dataclass
class ACEHeader:
    """
    https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-_ace_header
    """

    ace_type: ACEType
    ace_flags: ACEFlagsMask
    ace_size: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ACEHeader':
        return cls(
            ace_type=ACEType(struct_unpack('<B', data[0:1])[0]),
            ace_flags=ACEFlagsMask(struct_unpack('<B', data[1:2])[0]),
            ace_size=struct_unpack('<H', data[2:4])[0]
        )

    def __bytes__(self) -> bytes:
        return b''.join((
            struct_pack('<B', self.ace_type.value),
            struct_pack('<B', self.ace_flags.value),
            struct_pack('<H', self.ace_size)
        ))

    def __len__(self) -> int:
        return 4


class ActiveDirectoryRightsMask(IntFlag):
    """
    https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-__midl___midl_itf_ads_0001_0048_0001
    """

    ADS_RIGHT_DS_CREATE_CHILD = 0x1,
    ADS_RIGHT_DS_DELETE_CHILD = 0x2,
    ADS_RIGHT_ACTRL_DS_LIST = 0x4,
    ADS_RIGHT_DS_SELF = 0x8,
    ADS_RIGHT_DS_READ_PROP = 0x10,
    ADS_RIGHT_DS_WRITE_PROP = 0x20,
    ADS_RIGHT_DS_DELETE_TREE = 0x40,
    ADS_RIGHT_DS_LIST_OBJECT = 0x80,
    ADS_RIGHT_DS_CONTROL_ACCESS = 0x100,
    ADS_RIGHT_DELETE = 0x10000,
    ADS_RIGHT_READ_CONTROL = 0x20000,
    ADS_RIGHT_WRITE_DAC = 0x40000,
    ADS_RIGHT_WRITE_OWNER = 0x80000,
    ADS_RIGHT_SYNCHRONIZE = 0x100000,
    ADS_RIGHT_ACCESS_SYSTEM_SECURITY = 0x1000000,
    ADS_RIGHT_GENERIC_ALL = 0x10000000,
    ADS_RIGHT_GENERIC_EXECUTE = 0x20000000,
    ADS_RIGHT_GENERIC_WRITE = 0x40000000,
    ADS_RIGHT_GENERIC_READ = 0x80000000

    def __len__(self):
        return 4


class ACEObjectFlagMask(IntFlag):
    ACE_OBJECT_TYPE_PRESENT = 0x1
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

    def __len__(self):
        return 4


@dataclass
class ACE:
    header: ACEHeader
    access_mask: ActiveDirectoryRightsMask
    trustee_sid: SID

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ACE':
        header: ACEHeader = ACEHeader.from_bytes(data[0:4])
        access_mask: ActiveDirectoryRightsMask = ActiveDirectoryRightsMask(struct_unpack('<I', data[4:8])[0])

        ace_kwargs = dict(header=header, access_mask=access_mask)

        remaining_ace_size: int = header.ace_size - len(header) - len(access_mask)

        if header.ace_type in BASIC_ACE_TYPES:
            ace_kwargs['trustee_sid'] = SID.from_bytes(data[8:8+remaining_ace_size])
        else:
            if header.ace_type in OBJECT_ACE_TYPES:
                flags = ACEObjectFlagMask(struct_unpack('<I', data[8:12])[0])
                ace_kwargs['flags'] = flags

                if ACEObjectFlagMask.ACE_OBJECT_TYPE_PRESENT in flags and ACEObjectFlagMask.ACE_INHERITED_OBJECT_TYPE_PRESENT in flags:
                    object_type_offset: Optional[int] = 12
                    inherited_object_type_offset: Optional[int] = 28
                    sid_start_offset: int = 44
                elif ACEObjectFlagMask.ACE_OBJECT_TYPE_PRESENT in flags:
                    object_type_offset: Optional[int] = 12
                    inherited_object_type_offset: Optional[int] = None
                    sid_start_offset: int = 28
                elif ACEObjectFlagMask.ACE_INHERITED_OBJECT_TYPE_PRESENT in flags:
                    object_type_offset: Optional[int] = None
                    inherited_object_type_offset: Optional[int] = 12
                    sid_start_offset: int = 28
                else:
                    object_type_offset: Optional[int] = None
                    inherited_object_type_offset: Optional[int] = None
                    sid_start_offset: int = 12

                object_type: Optional[UUID] = UUID(bytes=data[object_type_offset:object_type_offset + 16]) \
                    if object_type_offset is not None else None
                inherited_object_type: Optional[UUID] = UUID(
                    bytes=data[inherited_object_type_offset:inherited_object_type_offset + 16]) \
                    if inherited_object_type_offset is not None else None

                ace_kwargs['object_type'] = object_type
                ace_kwargs['inherited_object_type'] = inherited_object_type

                remaining_ace_size = remaining_ace_size - len(flags) - (16 if object_type else 0) - (16 if inherited_object_type else 0)
            else:
                sid_start_offset = 8

            truestee_sid: SID = SID.from_bytes(data[sid_start_offset:])
            ace_kwargs['trustee_sid'] = truestee_sid
            remaining_ace_size -= len(truestee_sid)

            if header.ace_type in DATA_ACE_TYPES:
                ace_kwargs[
                    'attribute_data' if header.ace_type == ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE else 'application_data'
                ] = data[
                    sid_start_offset+len(truestee_sid):sid_start_offset+len(truestee_sid)+remaining_ace_size
                ]

        return ACE_TYPE_TO_ACE_CLASS[header.ace_type](**ace_kwargs)


@dataclass
class AccessAllowedACE(ACE):
    pass


@dataclass
class AccessAllowedObjectACE(ACE):
    flags: ACEObjectFlagMask
    object_type: Optional[UUID]
    inherited_object_type: Optional[UUID]


@dataclass
class AccessDeniedACE(ACE):
    pass


@dataclass
class AccessDeniedObjectACE(ACE):
    flags: ACEObjectFlagMask
    object_type: Optional[UUID]
    inherited_object_type: Optional[UUID]


@dataclass
class AccessAllowedCallbackACE(ACE):
    application_data: bytes


@dataclass
class AccessDeniedCallbackACE(ACE):
    application_data: bytes


@dataclass
class AccessAllowedCallbackObjectACE(ACE):
    flags: ACEObjectFlagMask
    object_type: Optional[UUID]
    inherited_object_type: Optional[UUID]
    application_data: bytes


@dataclass
class AccessDeniedCallbackObjectACE(ACE):
    flags: ACEObjectFlagMask
    object_type: Optional[UUID]
    inherited_object_type: Optional[UUID]
    application_data: bytes


@dataclass
class SystemAuditACE(ACE):
    pass


@dataclass
class SystemAuditObjectACE(ACE):
    flags: ACEObjectFlagMask
    object_type: Optional[UUID]
    inherited_object_type: Optional[UUID]
    application_data: bytes


@dataclass
class SystemAuditCallbackACE(ACE):
    application_data: bytes


# TODO: Look into
@dataclass
class SystemMandatoryLabelACE(ACE):
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a
    ...


@dataclass
class SystemAuditCallbackObjectACE(ACE):
    flags: ACEObjectFlagMask
    object_type: Optional[UUID]
    inherited_object_type: Optional[UUID]
    application_data: bytes


@dataclass
class SystemResourceAttributeACE(ACE):
    attribute_data: bytes


@dataclass
class SystemScopedPolicyIDACE(ACE):
    pass


ACE_TYPE_TO_ACE_CLASS = {
    ACEType.ACCESS_ALLOWED_ACE_TYPE: AccessAllowedACE,
    ACEType.ACCESS_DENIED_ACE_TYPE: AccessDeniedACE,
    ACEType.SYSTEM_AUDIT_ACE_TYPE: SystemAuditACE,
    # SYSTEM_ALARM_ACE_TYPE: 0x03,
    # ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04,
    ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE: AccessAllowedObjectACE,
    ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE: AccessDeniedObjectACE,
    ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE: SystemAuditObjectACE,
    # SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08,
    ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE: AccessAllowedCallbackACE,
    ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE: AccessDeniedCallbackACE,
    ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: AccessAllowedCallbackObjectACE,
    ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: AccessDeniedCallbackObjectACE,
    ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE: SystemAuditCallbackACE,
    # SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E,
    ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: SystemAuditCallbackObjectACE,
    # SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: 0x10,
    ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE: SystemMandatoryLabelACE,
    ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE: SystemResourceAttributeACE,
    ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: SystemScopedPolicyIDACE
}
