from typing import Optional, Union
from datetime import datetime, timedelta
from struct import unpack_from as struct_unpack_from


MS_EPOCH_INCEPTION = datetime(year=1601, month=1, day=1)


def ms_timestamp_to_filetime(ms_timestamp: int) -> bytes:
    ms_timestamp_bytes = ms_timestamp.to_bytes(length=8, byteorder='big', signed=False)

    # TODO: Verify that this is correct.
    return ms_timestamp_bytes[4:8][::-1] + ms_timestamp_bytes[0:4][::-1]

    # return b''.join([
    #     struct_pack('<I', ms_timestamp_bytes[4:8]),
    #     struct_pack('<I', ms_timestamp_bytes[0:4])
    # ])


def datetime_to_ms_timestamp(dt: datetime) -> int:
    # NOTE NOTE: Loss of precision?
    diff = dt - MS_EPOCH_INCEPTION
    return (diff.days * 86_400_000_000 + diff.seconds * 1_000_000 + diff.microseconds) * 10


def datetime_to_filetime(dt: datetime) -> bytes:
    return ms_timestamp_to_filetime(ms_timestamp=datetime_to_ms_timestamp(dt=dt))


def filetime_to_datetime(filetime: Union[int, bytes]) -> Optional[datetime]:
    """
    Convert a `FILETIME` value to a datetime object.

    A `FILETIME` value represents a period as a count of 100-nanosecond time slices. When interpreted as a
    timestamp, it should be considered in relation to the inception of the Windows epoch date: 1601-01-01.

    NOTE: There is a loss of precision when converting to a `datetime` object (tenth of a microsecond), because
    `datetime` only has microsecond precision.

    :param filetime: A `FILETIME` value as an integer or bytes.
    :return: A datetime object corresponding to the provided timestamp; `None` if it is blank.
    """

    if isinstance(filetime, bytes):
        filetime: int = struct_unpack_from('<Q', buffer=filetime, offset=0)[0]

    return (MS_EPOCH_INCEPTION + timedelta(microseconds=filetime // 10)) if filetime else None


def delta_time_to_filetime(delta_time: int) -> int:
    """
    Convert a signed 64-bit integer value with _delta syntax_ into its corresponding `FILETIME` value.

    A delta time value is a negative `FILETIME` value (which is also a signed 64-bit integer value). It represents a
    period of time expressed in a negative number of 100-nanosecond time slices.

    The delta time value is converted into a positive integer by way of the two’s complement conversion method, and is
    then parsed by `int.from_bytes` with the specified length of eight bytes and the signed flag.

    It has been observed that Microsoft has used the minimum signed 64-value 0x8000000000000000 to indicate an unset
    state for delta time attributes. When that value is passed to this function, an `OverflowError` is raised.

    :param delta_time: The delta time value to be converted.
    :return: The `FILETIME` value corresponding to the provided delta time value.
    """

    return int.from_bytes(
        bytes=(~delta_time + 1).to_bytes(length=8, byteorder='big', signed=True),
        byteorder='big'
    )
