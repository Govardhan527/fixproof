from importlib.metadata import version

import fixproof


def test_version_comes_from_distribution_metadata() -> None:
    assert fixproof.__version__ == version("fixproof")
