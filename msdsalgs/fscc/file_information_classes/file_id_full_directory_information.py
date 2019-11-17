from __future__ import annotations
from dataclasses import dataclass
from typing import ClassVar
from struct import unpack as struct_unpack

from .file_directory_information import FileDirectoryInformation
from msdsalgs.fscc.file_information import FileInformation


@dataclass
class FileIdFullDirectoryInformation(FileDirectoryInformation):
    ea_size: int
    file_id: bytes

    _reserved: ClassVar[int] = 4 * b'\x00'

    @classmethod
    def from_bytes(cls, data: bytes) -> FileIdFullDirectoryInformation:
        file_name_length: int = struct_unpack('<I', data[60:64])[0]
        return cls(
            next_entry_offset=struct_unpack('<I', data[:4])[0],
            file_index=struct_unpack('<I', data[4:8])[0],
            file_information=FileInformation.from_bytes(data=data[8:8+FileInformation.structure_size]),
            # TODO: Support "Reparse Tag" content.
            ea_size=struct_unpack('<I', data[64:68])[0],
            file_id=data[72:80],
            file_name=data[80:80+file_name_length].decode(encoding='utf-16-le')
        )
