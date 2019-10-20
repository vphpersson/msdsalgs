from typing import Tuple, Optional
from struct import unpack as struct_unpack, pack as struct_pack
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
        return struct_pack('<BBBBBB', *self.value)


class SID:
    def __init__(
        self,
        identifier_authority: IdentifierAuthority,
        sub_authorities: Tuple[int, ...],
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
    def from_string(cls, sid_string: str) -> 'SID':
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

    # TODO: Add another decorator that initiates an instance of `struct.Struct`? Or just refer to one using a property.
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SID':
        revision_number: int = struct_unpack('<B', data[0:1])[0]
        num_sub_authorities: int = struct_unpack('<B', data[1:2])[0]

        return cls(
            revision_number=revision_number,
            identifier_authority=IdentifierAuthority(struct_unpack('<BBBBBB', data[2:8])),
            sub_authorities=struct_unpack('<' + num_sub_authorities * 'I', data[8:8+4*num_sub_authorities])
        )

    def __str__(self) -> str:
        return f'S-1-{self.identifier_authority.value[-1]}-' \
            f'{"-".join(str(sub_authority) for sub_authority in self.sub_authorities)}'

    def __bytes__(self) -> bytes:
        return b''.join([
            struct_pack('<B', self._revision_number),
            struct_pack('<B', len(self.sub_authorities)),
            bytes(self.identifier_authority),
            struct_pack('<' + len(self.sub_authorities) * 'I', *self.sub_authorities)
        ])

    def __len__(self) -> int:
        # The size of the number of sub-authorities number, the size of the identifier authority tuple, and the size
        # of each sub-authority.
        return 2 + 6 + 4 * len(self.sub_authorities)


class DomainedSID(SID):

    @property
    def domain_id(self) -> Optional[Tuple[int, int, int]]:
        return self.sub_authorities[1:4] \
            if self.identifier_authority == IdentifierAuthority.SECURITY_NT_AUTHORITY and self.sub_authorities[0] == 21 \
            else None
