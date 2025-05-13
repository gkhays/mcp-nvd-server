
import re
import logging
import requests
from bs4 import BeautifulSoup

# Set up logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOGGER = logging.getLogger("rhsa")

def get_cves_from_rhsa(rhsa_id) -> list:
    """
    Scrape the Red Hat Security Portal to extract CVE numbers for a given RHSA ID.
    
    Args:
        rhsa_id (str): The Red Hat Security Advisory ID (e.g., "RHSA-2024-10379")
        
    Returns:
        list: List of CVE IDs associated with the RHSA
    """
    # Validate RHSA ID format
    # pattern = r'^RHSA-\d{4}:\d+$|^RHSA-\d{4}-\d+$'
    pattern = r'^RHSA-\d{4}:\d+$'
    if not re.match(pattern, rhsa_id):
        LOGGER.warning(f"Warning: Invalid RHSA ID format. Expected format: RHSA-YYYY:NNNN")
        if re.match(r'^RHSA-\d{4}-\d+$', rhsa_id):
            # Convert RHSA-YYYY-NNNN to RHSA-YYYY:NNNN
            rhsa_id = rhsa_id.rsplit("-", 1)[0] + ":" + rhsa_id.rsplit("-", 1)[1]
            LOGGER.info(f"Converted RHSA ID to valid format: {rhsa_id}")
        else:
            return []    
    
    url = f"https://access.redhat.com/errata/{rhsa_id}"
    
    try:
        LOGGER.info(f"Fetching data from {url}...")
        response = requests.get(url, timeout=10)        
        
        if response.status_code != 200:
            LOGGER.error(f"Error: Received status code {response.status_code}")
            return []        
        
        soup = BeautifulSoup(response.content, 'html.parser')        
        cve_list = []
        
        # Find CVE entries in the CVEs section
        cve_section = soup.find('section', {'id': 'cves'})
        if cve_section:
            LOGGER.info("Found CVE section in the page.")
            cve_links = cve_section.find_all('a', href=re.compile(r'CVE-\d{4}-\d+'))
            for link in cve_links:
                cve_match = re.search(r'(CVE-\d{4}-\d+)', link.text)
                if cve_match and cve_match.group(1) not in cve_list:
                    cve_list.append(cve_match.group(1))
        
        # Sometimes CVEs might be listed in a table
        cves_from_table = soup.find_all('td', string=re.compile(r'CVE-\d{4}-\d+'))
        for cve_cell in cves_from_table:
            cve_match = re.search(r'(CVE-\d{4}-\d+)', cve_cell.text)
            if cve_match and cve_match.group(1) not in cve_list:
                cve_list.append(cve_match.group(1))
        
        # Also look for CVEs in any text throughout the page
        all_text = soup.get_text()
        cve_matches = re.findall(r'CVE-\d{4}-\d+', all_text)
        for cve in cve_matches:
            if cve not in cve_list:
                cve_list.append(cve)
        
        return cve_list
        
    except requests.exceptions.RequestException as e:
        LOGGER.error(f"Error during request: {e}")
        return []
    except Exception as e:
        LOGGER.error(f"Unexpected error: {e}")
        return []
    