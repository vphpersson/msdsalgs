from __future__ import annotations
from dataclasses import dataclass
from struct import unpack as struct_unpack


@dataclass
class FileDirectoryInformation:
    next_entry_offset: int
    file_index: int
    file_information: FileInformation
    file_name: str

    @classmethod
    def from_bytes(cls, data: bytes) -> FileDirectoryInformation:
        file_name_length: int = struct_unpack('<I', data[60:64])[0]
        return cls(
            next_entry_offset=struct_unpack('<I', data[:4])[0],
            file_index=struct_unpack('<I', data[4:8])[0],
            file_information=FileInformation.from_bytes(data=data[8:8+FileInformation.structure_size]),
            file_name=data[64:64+file_name_length].decode(encoding='utf-16-le')
        )
