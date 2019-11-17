from enum import IntEnum

from .file_directory_information import FileDirectoryInformation
from .file_id_full_directory_information import FileIdFullDirectoryInformation


# TODO: These should be in caps, should they not?
# TODO: Complement.
class FileInformationClass(IntEnum):
    FileDirectoryInformation = 0x01
    FileFullDirectoryInformation = 0x02
    FileIdFullDirectoryInformation = 0x26
    FileBothDirectoryInformation = 0x03
    FileIdBothDirectoryInformation = 0x25
    FileNamesInformation = 0x0C
