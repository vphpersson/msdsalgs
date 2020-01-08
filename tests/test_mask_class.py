from enum import IntFlag
from msdsalgs.utils import Mask
from pytest import raises as pytest_raises


class SCManagerAccessFlag(IntFlag):
    SC_MANAGER_LOCK = 0x00000008
    SC_MANAGER_CREATE_SERVICE = 0x00000002
    SC_MANAGER_ENUMERATE_SERVICE = 0x00000004
    SC_MANAGER_CONNECT = 0x00000001
    SC_MANAGER_QUERY_LOCK_STATUS = 0x00000010
    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020


SCManagerAccessFlagMask = Mask.make_class(
    int_flag_class=SCManagerAccessFlag,
    prefix='SC_MANAGER_'
)


def test_empty_constructor():
    mask = SCManagerAccessFlagMask()

    assert int(mask) == 0
    assert all(not value for _, value in mask.items())


def test_from_int():
    mask = SCManagerAccessFlagMask.from_int(7)
    assert mask.connect and mask.create_service and mask.enumerate_service


def test_to_int():
    int_mask = 7
    mask = SCManagerAccessFlagMask.from_int(int_mask)
    assert int(mask) == int_mask


def test_to_int_flag():
    mask = SCManagerAccessFlagMask(connect=True, create_service=True, enumerate_service=True)
    assert mask.to_int_flag() == (
        SCManagerAccessFlag.SC_MANAGER_CONNECT
        | SCManagerAccessFlag.SC_MANAGER_CREATE_SERVICE
        | SCManagerAccessFlag.SC_MANAGER_ENUMERATE_SERVICE
    )


def test_set_all():
    mask = SCManagerAccessFlagMask()
    mask.set_all()

    assert all(value for _, value in mask.items())


def test_clear_all():
    mask = SCManagerAccessFlagMask()
    mask.set_all()
    mask.clear_all()

    assert all(not value for _, value in mask.items())


def test_setter():
    mask = SCManagerAccessFlagMask()

    assert all(not value for _, value in mask.items())

    mask.connect = True
    mask.create_service = True

    assert int(mask) == 3
    assert mask.to_int_flag() == (
        SCManagerAccessFlag.SC_MANAGER_CONNECT
        | SCManagerAccessFlag.SC_MANAGER_CREATE_SERVICE
    )

    mask.connect = False

    assert int(mask) == 2
    assert mask.to_int_flag() == SCManagerAccessFlag.SC_MANAGER_CREATE_SERVICE

    mask.create_service = False

    assert int(mask) == 0
    assert mask.to_int_flag() == 0


def test_items():
    mask = SCManagerAccessFlagMask()
    assert mask.items() == (
        ('connect', False),
        ('create_service', False),
        ('enumerate_service', False),
        ('lock', False),
        ('modify_boot_config', False),
        ('query_lock_status', False)
    )



def test_incorrect_paramaters():
    with pytest_raises(ValueError):
        SCManagerAccessFlagMask(incorrect_parameter=False)

    with pytest_raises(ValueError):
        SCManagerAccessFlagMask(connect=True, incorrect_parameter=True)
