import json

from hardening_agent.advisor import OllamaAdvisor


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_hardening_review_repairs_truncated_json_once(monkeypatch) -> None:
    repaired = {
        "summary": "Kompakte Auswahl",
        "profile_name": "KI-Basis",
        "recommendations": [],
        "warnings": [],
    }
    responses = iter(
        [
            _Response({"message": {"content": '{"summary":"abgeschnitten'}}),
            _Response({"message": {"content": json.dumps(repaired)}}),
        ]
    )
    requests = []

    def fake_urlopen(request, timeout):
        requests.append((request, timeout))
        return next(responses)

    monkeypatch.setattr("hardening_agent.advisor.urllib.request.urlopen", fake_urlopen)

    result = OllamaAdvisor(model="qwen3:8b", timeout=20).prioritize_hardening(
        {"distribution": "debian", "version": "13"},
        [],
    )

    assert result == repaired
    assert len(requests) == 2
    first_payload = json.loads(requests[0][0].data)
    assert first_payload["options"]["num_predict"] == 3072
