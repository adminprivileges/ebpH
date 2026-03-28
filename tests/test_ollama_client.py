import json

import pytest

from ebph.ollama_client import OllamaAdjudicatorClient, OllamaAdjudicatorError


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def test_ollama_client_success_parse(monkeypatch):
    client = OllamaAdjudicatorClient(
        base_url='http://127.0.0.1:11434',
        model='test-model',
        timeout_sec=0.2,
        keep_alive='0',
    )

    payload = {
        'message': {
            'content': json.dumps({
                'detected': True,
                'confidence': 1.2,
                'reason_code': 'suspicious_pattern',
                'rationale': 'high density',
            })
        }
    }

    def fake_urlopen(_req, timeout=0):
        assert timeout == 0.2
        return _FakeResponse(json.dumps(payload).encode('utf-8'))

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    out = client.adjudicate({'decision': {}, 'routing': {}, 'process': {}, 'scope_profile': {}, 'experiment': {}})
    assert out['detected'] is True
    assert out['confidence'] == 1.0


def test_ollama_client_invalid_json(monkeypatch):
    client = OllamaAdjudicatorClient(
        base_url='http://127.0.0.1:11434',
        model='test-model',
        timeout_sec=0.2,
        keep_alive='0',
    )

    payload = {'message': {'content': '{bad-json]'}}

    def fake_urlopen(_req, timeout=0):
        return _FakeResponse(json.dumps(payload).encode('utf-8'))

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    with pytest.raises(OllamaAdjudicatorError):
        client.adjudicate({'decision': {}, 'routing': {}, 'process': {}, 'scope_profile': {}, 'experiment': {}})


def test_ollama_client_timeout(monkeypatch):
    client = OllamaAdjudicatorClient(
        base_url='http://127.0.0.1:11434',
        model='test-model',
        timeout_sec=0.2,
        keep_alive='0',
    )

    def fake_urlopen(_req, timeout=0):
        raise TimeoutError('timed out')

    monkeypatch.setattr('urllib.request.urlopen', fake_urlopen)
    with pytest.raises(OllamaAdjudicatorError):
        client.adjudicate({'decision': {}, 'routing': {}, 'process': {}, 'scope_profile': {}, 'experiment': {}})
