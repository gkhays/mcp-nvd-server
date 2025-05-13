import logging
import requests
import re

LOGGER = logging.getLogger("mcp-nvd")

class NVD:    
    def __init__(
            self, 
            cve_json = None,
            description = None,
            severity = None,
            base_url = None
        ):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        LOGGER.debug(f"Initializing NVD with URL: {base_url}")

    def get_cve_list(self, cve_id: str) -> list:
        """
        Retrieve a specific CVE by its ID.

        Args:
            cve_id (str): The CVE ID (e.g. CVE-2025-12345)
        
        Returns:
            dict: CVE item or None if not found
        """
        LOGGER.info(f"Validating CVE ID: {cve_id}")
        if not self.validate_cve_id(cve_id):
            LOGGER.error(f"Invalid CVE ID format: {cve_id}")
            raise ValueError(f"Invalid CVE ID format: {cve_id}")        

        params = {
            "cveId": cve_id,
        }

        LOGGER.info(f"Fetching CVE: {cve_id}...")

        try:
            response = requests.get(self.base_url, params=params)

            if response.status_code == 200:
                LOGGER.info(f"Response: {response.status_code}")
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])

                if vulnerabilities:
                    self.cve_json = vulnerabilities[0]
                    self.description = self.get_description()
                    LOGGER.info(f"Description: {self.description}")
                    return vulnerabilities
                else:
                    LOGGER.info(f"CVE {self.cve_id} not found in NVD database.")
                    return None
                
            elif response.status_code == 403:
                print("Error: API rate limit exceeded. Please try again later.")
                return None
            elif response.status_code == 404:
                print("Error: API endpoint not found. Checking for diagnostic information...")
                print(f"Response: {response.text}")
                print("\nTrying alternative API endpoint...")
            else:
                print(f"Error: API returned status code {response.status_code}")
                print(f"Response: {response.text}")
                return None

        except Exception as e:
            print(f"Error: {e}")
            return None

    def get_description(self, country_code='en') -> str:
        """
        Retrieve the description of the CVE in the specified language.

        Args:
            country_code (str): Language code (e.g. 'en', 'fr', etc.)
        
        Returns:
            str: Description in the specified language or None if not found
        """
        if self.cve_json:
            descriptions = self.cve_json.get('cve', {}).get('descriptions', [])
            for description in descriptions:
                if description.get('lang') == country_code:
                    return description.get('value')
                return None
    
    def normalize_rhsa_id(self, rhsa_id) -> str:
        """
        Validates the format of a RHSA ID.

        Args:
            rhsa_id (str): The RHSA ID to validate.

        Returns:
            str: The normalized RHSA ID if valid, otherwise the original RHSA ID.
        """
        pattern = r'^RHSA-\d{4}:\d+$'
        if not re.match(pattern, rhsa_id):
            LOGGER.warning(f"Invalid RHSA ID: {rhsa_id}. Expected format: RHSA-YYYY:NNNN")
            if re.match(r'^RHSA-\d{4}-\d+$', rhsa_id):
                new_id = rhsa_id.rsplit("-", 1)[0] + ":" + rhsa_id.rsplit("-", 1)[1]
                LOGGER.info(f"Converted RHSA ID to valid format: {new_id}")
                return new_id
        return rhsa_id

    def search_vulnerabilities(self, query):
        """
        Searches for vulnerabilities in the NVD based on a query.
        """
        pass

    def validate_cve_id(self, cve_id):
        """
        Validates the format of a CVE ID.

        Args:
            cve_id (str): The CVE ID to validate.

        Returns:
            bool: True if the CVE ID is valid, False otherwise.
        """
        pattern = r'^CVE-\d{4}-\d{4,7}$'
        if not re.match(pattern, cve_id):
            LOGGER.info(f"Invalid CVE ID: {cve_id}")
            return False
        return True
    