from dataclasses import dataclass
from typing import Tuple, List
from struct import unpack as struct_unpack

from ad_data_gatherer.utils.microsoft_structures.ace import ACE


@dataclass
class ACLPacket:
    """
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
    """

    # TODO: Make `ClassVar`s.

    revision: int
    _sbz1: int
    _size: int
    ace_count: int
    _sbz2: int

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ACLPacket':

        # TODO: Revision should also be checked, maybe.
        #   https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428

        sbz1: int = struct_unpack('<B', data[1:2])[0]
        if sbz1 != 0:
            raise ValueError(f'sbz1 is reserved and must be set to `0`.')

        sbz2: int = struct_unpack('<H', data[6:8])[0]
        if sbz2 != 0:
            raise ValueError(f'sbz2 is reserved and must be set to `0`.')

        # TODO: Verify?
        size: int = struct_unpack('<H', data[2:4])[0]

        return cls(
            revision=struct_unpack('<B', data[0:1])[0],
            _sbz1=sbz1,
            _size=size,
            ace_count=struct_unpack('<H', data[4:6])[0],
            _sbz2=sbz2
        )


@dataclass
class ACL:
    _packet: ACLPacket
    aces: Tuple[ACE, ...]

    @classmethod
    def from_bytes(cls, data: bytes) -> 'ACL':
        """
        Construct an ACL from a byte stream.

        :param data: The bytes constituting the ACL.
        :return: An ACL.
        """

        acl_packet: ACLPacket = ACLPacket.from_bytes(data[0:8])

        aces: List[ACE] = []
        # The exact position of each ACE is not yet known. The size of each individual ACE is variable, and can only be
        # known after parsing the ACE's header. The position from where to start the parsing of an ACE is calculated
        # from the size of all previously parsed ACEs via the `ace_data_offset` variable. `8` is the starting position.
        ace_data_offset = 8
        for i in range(acl_packet.ace_count):
            ace = ACE.from_bytes(data[ace_data_offset:])
            aces.append(ace)
            ace_data_offset += ace.header.ace_size

        return cls(
            _packet=acl_packet,
            aces=tuple(aces)
        )


@dataclass
class SACL(ACL):
    pass


@dataclass
class DACL(ACL):
    pass
