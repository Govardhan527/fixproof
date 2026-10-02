import copy

from fixproof import sanitize
from tool_outputs import output


def test_sanitising_never_changes_the_input() -> None:
    for tool, clean in (("grype", sanitize.grype), ("syft", sanitize.syft)):
        original = output(tool, "vulnerable")
        before = copy.deepcopy(original)
        clean(original)
        assert original == before


def test_unexpected_shapes_are_left_alone() -> None:
    assert sanitize.grype({"source": {"target": "dir:/x"}}) == {"source": {"target": "dir:/x"}}
    assert sanitize.syft({"source": {}, "descriptor": "x"}) == {"source": {}, "descriptor": "x"}


def test_only_the_named_fields_go() -> None:
    clean = sanitize.grype(output("grype", "vulnerable"))
    assert set(clean) == {"matches", "source", "distro", "descriptor"}
    assert set(clean["descriptor"]["db"]["status"]) == {"schemaVersion", "from", "built", "valid"}
    assert "manifestDigest" in clean["source"]["target"]
