from __future__ import annotations
from enum import IntEnum
from struct import unpack as struct_unpack, pack as struct_pack
from typing import ClassVar
from dataclasses import dataclass


class FileNotifyAction(IntEnum):
    FILE_ACTION_ADDED = 0x00000001,
    FILE_ACTION_REMOVED = 0x00000002,
    FILE_ACTION_MODIFIED = 0x00000003,
    FILE_ACTION_RENAMED_OLD_NAME = 0x00000004,
    FILE_ACTION_RENAMED_NEW_NAME = 0x00000005,
    FILE_ACTION_ADDED_STREAM = 0x00000006,
    FILE_ACTION_REMOVED_STREAM = 0x00000007,
    FILE_ACTION_MODIFIED_STREAM = 0x00000008,
    FILE_ACTION_REMOVED_BY_DELETE = 0x00000009,
    FILE_ACTION_ID_NOT_TUNNELLED = 0x0000000A,
    FILE_ACTION_TUNNELLED_ID_COLLISION = 0x0000000B


@dataclass
class FileNotifyInformation:
    next_entry_offset: int
    action: FileNotifyAction
    file_name: str

    # NOTE: I defined this, not the docs.
    structure_size: ClassVar[int] = 12

    @classmethod
    def from_bytes(cls, data: bytes) -> FileNotifyInformation:

        file_name_len: int = struct_unpack('<I', data[8:12])[0]

        return cls(
            next_entry_offset=struct_unpack('<I', data[:4])[0],
            action=FileNotifyAction(struct_unpack('<I', data[4:8])[0]),
            file_name=data[12:12+file_name_len].decode(encoding='utf-16-le')
        )

    def __len__(self) -> int:
        return self.structure_size + len(self.file_name.encode(encoding='utf-16-le'))

    def __bytes__(self) -> bytes:
        file_name_bytes: bytes = self.file_name.encode(encoding='utf-16-le')
        return b''.join([
            struct_pack('<I', self.next_entry_offset),
            struct_pack('<I', self.action.value),
            struct_pack('<I', len(file_name_bytes)),
            file_name_bytes
        ])
