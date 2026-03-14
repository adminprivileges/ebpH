from ebph import defs
from ebph.ebphd import parse_args
from ebph.utils import compose_profile_key, calculate_profile_key_from_stat, get_process_executable_key


class _FakeStat:
    def __init__(self, st_dev, st_ino):
        self.st_dev = st_dev
        self.st_ino = st_ino


def test_parse_scope_mode_host():
    args = parse_args('--nodaemon --scope-mode host'.split())
    assert args.scope_mode == defs.SCOPE_MODE_HOST


def test_parse_scope_mode_container():
    args = parse_args('--nodaemon --scope-mode container'.split())
    assert args.scope_mode == defs.SCOPE_MODE_CONTAINER


def test_parse_bootstrap_mode_never():
    args = parse_args('--nodaemon --bootstrap-mode never'.split())
    assert args.bootstrap_mode == 'never'


def test_parse_bootstrap_mode_always():
    args = parse_args('--nodaemon --bootstrap-mode always'.split())
    assert args.bootstrap_mode == 'always'


def test_compose_profile_key_host_compatibility():
    executable_key = 0x12345678
    assert compose_profile_key(0, executable_key) == executable_key


def test_compose_profile_key_scope_sensitive():
    executable_key = 0xABCDEF
    assert compose_profile_key(1, executable_key) != compose_profile_key(2, executable_key)


def test_calculate_profile_key_from_stat():
    s = _FakeStat(12, 34)
    assert calculate_profile_key_from_stat(s) == (12 << 32 | 34)


def test_get_process_executable_key_fallback(monkeypatch):
    import ebph.utils as utils

    def fake_stat(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(utils.os, 'stat', fake_stat)
    monkeypatch.setattr(utils, 'calculate_profile_key', lambda p: 0x1337)

    assert get_process_executable_key(1234, '/fake/exe') == 0x1337
