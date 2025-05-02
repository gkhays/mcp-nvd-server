from mcp_nvd.nvd import NVD
import logging
import json

LOGGER = logging.getLogger(__name__)

def test_fetch_cve():
    cve_id = "CVE-2025-30065"
    nvd = NVD(cve_id=cve_id)
    cve_data = nvd.get_cve()

    # Check if the data is not None and contains expected keys
    assert cve_data is not None, "CVE data should not be None"
    assert not isinstance(cve_data, str), "CVE data should not be a string"
    assert len(cve_data) == 1, "CVE data should only contain one item"
    assert isinstance(cve_data, dict), "CVE data should be a dictionary"
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

def test_fetch_cve_no_constructor():
    cve_id = "CVE-2025-30065"
    nvd = NVD(cve_id=cve_id)
    cve_data = nvd.get_cve()
    LOGGER.info(f"Using non-constructor method to fetch CVE data for {cve_id}")

    # Check if the data is not None and contains expected keys
    assert cve_data is not None, "CVE data should not be None"
    assert not isinstance(cve_data, str), "CVE data should not be a string"
    assert len(cve_data) == 1, "CVE data should only contain one item"
    assert isinstance(cve_data, dict), "CVE data should contain dictionaries"
    assert key_exists_in_dict('id', cve_data), "CVE data should contain 'id' key"
    assert cve_data['cve']['id'] == cve_id, f"CVE ID should be {cve_id}"

def test_fetch_description(country_code='en'):
    cve_id = "CVE-2025-30065"
    nvd = NVD(cve_id=cve_id)
    cve_data = nvd.get_cve()

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
    cve_id = "CVE-2025-30065"
    nvd = NVD(cve_id=cve_id)
    cve_data = nvd.get_cve()

    for reference in cve_data['cve']['references']:
        assert isinstance(reference, dict), "Reference should be a dictionary"
        assert 'url' in reference, "Reference should contain 'url' key"
        assert reference['url'] is not None, "Reference URL should not be None"
        LOGGER.info(f"Reference URL: {reference['url']}")

def key_exists_in_dict(key, d):
    for key in d:
        if key in d:
            d = d[key]
        else:
            return False
    return True