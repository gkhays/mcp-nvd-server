import pytest
from mcp_nvd.nvd import NVD
import logging

import rhsa

LOGGER = logging.getLogger(__name__)

CVE_ID = "CVE-2025-30065"

def test_fetch_cve():
    cve_id = CVE_ID
    nvd = NVD()
    cve_list = nvd.get_cve_list(cve_id)
    cve_data = cve_list[0] if cve_list else None
    LOGGER.info(f"Using constructor method to fetch CVE data for {cve_id}")

    # Check if the data is not None and contains expected keys
    assert cve_data is not None, "CVE data should not be None"
    assert not isinstance(cve_data, str), "CVE data should not be a string"
    assert len(cve_data) > 0, "CVE data should only contain one item"
    assert isinstance(cve_list, list), "CVE data should be a list"
    assert isinstance(cve_data, dict), "CVE data should contain dictionaries"
    assert key_exists_in_dict('id', cve_data), "CVE data should contain 'id' key"
    assert cve_data['cve']['id'] == cve_id, f"CVE ID should be {cve_id}"

    assert key_exists_in_dict('description', cve_data), "CVE data should contain 'description' key"
    assert len(cve_data['cve']['descriptions']) > 0, "CVE data should contain 1 or more descriptions"
    for description in cve_data['cve']['descriptions']:
        assert isinstance(description, dict), "Description should be a dictionary"
        assert 'value' in description, "Description should contain 'value' key"
        assert description['value'] is not None, "Description value should not be None"
        LOGGER.info(f"Description ({description['lang']}) value: {description['value']}")

    assert key_exists_in_dict('references', cve_data), "CVE data should contain 'references' key"
    assert cve_data['cve']['references'] is not None, "CVE data should contain references"
    assert cve_data['cve']['references'][0]['url'] is not None, "CVE data should contain 'url' key in references"
    LOGGER.info(f"Reference check: {cve_data['cve']['references'][0]['url']}")

def test_fetch_description(country_code='en'):
    cve_id = CVE_ID
    nvd = NVD()
    cve_list = nvd.get_cve_list(cve_id)
    cve_data = cve_list[0] if cve_list else None    

    descriptions = cve_data['cve']['descriptions']
    description_value = None
    for description in descriptions:
        if description.get('lang') == country_code:
            description_value = description.get('value')
            break
        else:
            pass

    assert description_value is not None, f"No description found for language '{country_code}'"
    LOGGER.info(f"Description for language '{country_code}': {description_value}")

def test_fetch_references():
    cve_id = CVE_ID
    nvd = NVD()
    cve_list = nvd.get_cve_list(cve_id)
    cve_data = cve_list[0] if cve_list else None

    for reference in cve_data['cve']['references']:
        assert isinstance(reference, dict), "Reference should be a dictionary"
        assert 'url' in reference, "Reference should contain 'url' key"
        assert reference['url'] is not None, "Reference URL should not be None"
        LOGGER.info(f"Reference URL: {reference['url']}")

def test_get_cves_from_rhsa():
    rhsa_id = "RHSA-2024-10379"
    cve_list = rhsa.get_cves_from_rhsa(rhsa_id=rhsa_id)
    assert isinstance(cve_list, list), "CVE list should be a list"
    assert len(cve_list) > 0, "CVE list should not be empty"

    nvd = NVD()
    for cve in cve_list:
        assert isinstance(cve, str), "CVE should be a string"
        LOGGER.info(f"CVE from RHSA: {cve}")

        nvd.cve_id = cve
        cve_data = nvd.get_cve_list(cve)
        assert cve_data is not None, f"CVE data should not be None for {cve}"
        assert isinstance(cve_data, list), "CVE data should be a list"
        assert len(cve_data) > 0, f"CVE data should not be empty for {cve}"
        assert isinstance(cve_data[0], dict), "CVE data should contain dictionaries"
        LOGGER.info(f"CVE data for {cve}: {cve_data[0]}")

def test_fetch_cve_with_invalid_id():
    invalid_cve_id = "RHSA-2024:10379"
    nvd = NVD()

    assert not nvd.validate_cve_id(invalid_cve_id), f"Invalid CVE ID should not be valid: {invalid_cve_id}"

    with pytest.raises(ValueError) as excinfo:
        cve_list = nvd.get_cve_list(invalid_cve_id)
    assert "Invalid CVE ID" in str(excinfo.value), f"Expected ValueError for invalid CVE ID: {invalid_cve_id}"

def key_exists_in_dict(key, d):
    for key in d:
        if key in d:
            d = d[key]
        else:
            return False
    return True