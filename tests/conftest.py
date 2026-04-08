import pytest
from unittest.mock import MagicMock


SCAN_TIMESTAMP = "2026-01-01T00:00:00+00:00"
PROJECT_ID = "test-project"


def make_asset(asset_type, name="//compute.googleapis.com/projects/test/resource"):
    asset = MagicMock()
    asset.asset_type = asset_type
    asset.name = name
    return asset
