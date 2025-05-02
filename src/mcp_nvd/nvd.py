import logging
import requests

LOGGER = logging.getLogger("mcp-nvd")

class NVD:
    def __new__(cls, *args, **kwargs):
        """
        This method is called when an instance of the class is created.
        It ensures that only one instance of the class is created (singleton pattern).
        """
        if not hasattr(cls, 'instance'):
            cls.instance = super(NVD, cls).__new__(cls)
        return cls.instance
    
    def __init__(
            self, 
            cve_id = None,
            cve_json = None,
            description = None,
            severity = None,
            base_url = None
        ):
        self.cve_id = cve_id
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        LOGGER.debug(f"Initializing NVD with CVE ID: {cve_id}")

    def get_cve(self) -> dict:
        """
        Retrieve a specific CVE by its ID.

        Args:
            cve_id (str): The CVE ID (e.g. CVE-2025-12345)
        
        Returns:
            dict: CVE item or None if not found
        """
        params = {
            "cveId": self.cve_id,
        }

        LOGGER.info(f"Fetching CVE: {self.cve_id}...")

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
                    return vulnerabilities[0]
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

    def search_vulnerabilities(self, query):
        """
        Searches for vulnerabilities in the NVD based on a query.
        """
        pass