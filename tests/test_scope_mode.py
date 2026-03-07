from ebph import defs
from ebph.ebphd import parse_args
from ebph.utils import compose_profile_key


def test_parse_scope_mode_host():
    args = parse_args('--nodaemon --scope-mode host'.split())
    assert args.scope_mode == defs.SCOPE_MODE_HOST


def test_parse_scope_mode_container():
    args = parse_args('--nodaemon --scope-mode container'.split())
    assert args.scope_mode == defs.SCOPE_MODE_CONTAINER


def test_compose_profile_key_host_compatibility():
    executable_key = 0x12345678
    assert compose_profile_key(0, executable_key) == executable_key


def test_compose_profile_key_scope_sensitive():
    executable_key = 0xABCDEF
    assert compose_profile_key(1, executable_key) != compose_profile_key(2, executable_key)
