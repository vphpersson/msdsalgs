from __future__ import annotations
from typing import Optional, ByteString
from struct import unpack_from, pack, Struct, calcsize
from enum import Enum
from re import compile as re_compile

SID_STR_PATTERN = re_compile(r'^S-(?P<revision_number>\d+)-(?P<identifier_authority_num>\d+)(?P<sub_authority_str>(?:-\d+)+)$')


class WellKnownSidStr(Enum):
    ADMINISTRATORS_GROUP = 'S-1-5-32-544'
    REMOTE_DESKTOP_USERS_GROUP = 'S-1-5-32-555'


class IdentifierAuthority(Enum):
    NULL_SID_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    WORLD_SID_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x01)
    LOCAL_SID_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x02)
    CREATOR_SID_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x03)
    NON_UNIQUE_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x04)
    SECURITY_NT_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x05)
    SECURITY_APP_PACKAGE_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x0F)
    SECURITY_MANDATORY_LABEL_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x10)
    SECURITY_SCOPED_POLICY_ID_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x11)
    SECURITY_AUTHENTICATION_AUTHORITY = (0x00, 0x00, 0x00, 0x00, 0x00, 0x12)

    def __bytes__(self) -> bytes:
        return pack('<BBBBBB', *self.value)


class SID:
    def __init__(
        self,
        identifier_authority: IdentifierAuthority,
        sub_authorities: tuple[int, ...],
        revision_number: int = 1
    ):
        """
        Construct a SID.

        :param identifier_authority: The identifier authority of the security principal.
        :param sub_authorities: The sub-authorities of the security principal.
        :param revision_number: The revision number. Must be set to `1`.
        """

        if len(sub_authorities) > 15:
            raise ValueError('The maximum number of sub-authorities is 15.')

        self._revision_number = revision_number
        self.identifier_authority = identifier_authority
        self.sub_authorities = sub_authorities

    @property
    def revision_number(self) -> int:
        return self._revision_number

    @revision_number.setter
    def revision_number(self, revision_number: int) -> None:
        if revision_number != 0x01:
            raise ValueError('The revision number must be `1`.')

        self._revision_number = revision_number

    @property
    def rid(self) -> int:
        return self.sub_authorities[-1]

    @classmethod
    def from_string(cls, sid_string: str) -> SID:
        match = SID_STR_PATTERN.match(sid_string)
        if match is None:
            raise ValueError('Not a valid SID string.')

        return cls(
            revision_number=int(match.group('revision_number')),
            identifier_authority=IdentifierAuthority(
                value=(0x00, 0x00, 0x00, 0x00, 0x00, int(match.group('identifier_authority_num')))
            ),
            sub_authorities=tuple(int(part) for part in match.group('sub_authority_str')[1:].split('-'))
        )

    _REVISION_NUMBER_STRUCT = Struct('<B')
    _NUM_SUB_AUTHORITIES_STRUCT = Struct('<B')
    _IDENTIFIER_AUTHORITY_STRUCT = Struct('<BBBBBB')
    _SUB_AUTHORITY_STRUCT_FORMAT = 'I'

    @classmethod
    def from_bytes(cls, data: ByteString, base_offset: int = 0) -> SID:
        data = memoryview(data)[base_offset:]
        offset = 0

        revision_number: int = cls._REVISION_NUMBER_STRUCT.unpack_from(buffer=data, offset=offset)[0]
        offset += cls._REVISION_NUMBER_STRUCT.size

        num_sub_authorities: int = cls._NUM_SUB_AUTHORITIES_STRUCT.unpack_from(buffer=data, offset=offset)[0]
        offset += cls._NUM_SUB_AUTHORITIES_STRUCT.size

        identifier_authority = IdentifierAuthority(
            cls._IDENTIFIER_AUTHORITY_STRUCT.unpack_from(buffer=data, offset=offset)
        )
        offset += cls._IDENTIFIER_AUTHORITY_STRUCT.size

        sub_authorities: tuple[int, ...] = unpack_from(
            '<' + num_sub_authorities * cls._SUB_AUTHORITY_STRUCT_FORMAT,
            buffer=data,
            offset=offset
        )

        return cls(
            revision_number=revision_number,
            identifier_authority=identifier_authority,
            sub_authorities=sub_authorities
        )

    def __str__(self) -> str:
        return f'S-1-{self.identifier_authority.value[-1]}-' \
            f'{"-".join(str(sub_authority) for sub_authority in self.sub_authorities)}'

    def __bytes__(self) -> bytes:
        return b''.join([
            self._REVISION_NUMBER_STRUCT.pack(self._revision_number),
            self._NUM_SUB_AUTHORITIES_STRUCT.pack(len(self.sub_authorities)),
            self._IDENTIFIER_AUTHORITY_STRUCT.pack(self.identifier_authority.value),
            pack('<' + len(self.sub_authorities) * self._SUB_AUTHORITY_STRUCT_FORMAT, *self.sub_authorities)
        ])

    def __len__(self) -> int:
        return (
            self._REVISION_NUMBER_STRUCT.size
            + self._NUM_SUB_AUTHORITIES_STRUCT.size
            + self._IDENTIFIER_AUTHORITY_STRUCT.size
            + calcsize(self._SUB_AUTHORITY_STRUCT_FORMAT) * len(self.sub_authorities)
        )


class DomainedSID(SID):

    @property
    def domain_id(self) -> Optional[tuple[int, int, int]]:
        return self.sub_authorities[1:4] \
            if self.identifier_authority == IdentifierAuthority.SECURITY_NT_AUTHORITY and self.sub_authorities[0] == 21 \
            else None
