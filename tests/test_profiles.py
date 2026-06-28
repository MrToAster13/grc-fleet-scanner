"""Tests for grc_auditor.profiles: datastream/profile registry (pure)."""

from __future__ import annotations

import pytest

from grc_auditor import profiles


def test_datastream_for_known_versions():
    assert profiles.datastream_for_version("18.04") == "ssg-ubuntu1804-ds.xml"
    assert profiles.datastream_for_version("20.04") == "ssg-ubuntu2004-ds.xml"
    assert profiles.datastream_for_version("22.04") == "ssg-ubuntu2204-ds.xml"
    assert profiles.datastream_for_version("24.04") == "ssg-ubuntu2404-ds.xml"


def test_datastream_for_unknown_version_is_none():
    assert profiles.datastream_for_version("16.04") is None
    assert profiles.datastream_for_version("99.99") is None
    assert profiles.datastream_for_version("") is None


def test_datastream_for_point_release_normalizes_to_lts():
    # "22.04.3" -> "22.04"; quoted/padded versions are also normalized.
    assert profiles.datastream_for_version("22.04.3") == "ssg-ubuntu2204-ds.xml"
    assert profiles.datastream_for_version(' "20.04" ') == "ssg-ubuntu2004-ds.xml"


def test_datastream_path_default_dir():
    assert (
        profiles.datastream_path("22.04")
        == "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
    )


def test_datastream_path_custom_dir_strips_trailing_slash():
    assert (
        profiles.datastream_path("20.04", "/opt/ssg/")
        == "/opt/ssg/ssg-ubuntu2004-ds.xml"
    )


def test_datastream_path_unknown_version_is_none():
    assert profiles.datastream_path("16.04") is None


def test_profile_id_levels_1_and_2():
    assert (
        profiles.profile_id(1)
        == "xccdf_org.ssgproject.content_profile_cis_level1_server"
    )
    assert (
        profiles.profile_id(2)
        == "xccdf_org.ssgproject.content_profile_cis_level2_server"
    )


def test_profile_id_invalid_level_raises():
    with pytest.raises(ValueError):
        profiles.profile_id(3)
    with pytest.raises(ValueError):
        profiles.profile_id(0)


def test_supported_versions_sorted():
    versions = profiles.supported_versions()
    assert versions == sorted(versions)
    assert versions == ["18.04", "20.04", "22.04", "24.04"]
