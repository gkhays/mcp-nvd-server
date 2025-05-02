class CVE:
    def __init__(
            self, 
            cve_id, 
            description, 
            severity, 
            published_date, 
            last_modified_date
        ):
        self.cve_id = cve_id
        self.description = description
        self.severity = severity
        self.published_date = published_date
        self.last_modified_date = last_modified_date

    def __str__(self):
        """
        Return a string representation of the CVE object.
        """
        return (f"CVE ID: {self.cve_id}\n"
                f"Description: {self.description}\n"
                f"Severity: {self.severity}\n"
                f"Published Date: {self.published_date}\n"
                f"Last Modified Date: {self.last_modified_date}")

    def get_description(self) -> str:
        return self.description
    
    def is_critical(self):
        return self.severity.lower() == "critical"
    
    def is_high(self):
        return self.severity.lower() == "high"
