import nmap
import requests
import json
import socket
from datetime import datetime

class VulnerabilityScanner:
    def __init__(self, target, ports="1-1000"):
        self.target = target
        self.ports = ports
        self.vulnerabilities = []  # Initialize vulnerabilities list
        try:
            # Explicitly specify the Nmap executable path
            self.nm = nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap\\nmap.exe',))
        except NameError:
            raise Exception("python-nmap module not installed. Please install it using 'pip install python-nmap' and ensure Nmap is installed on your system.")

    def scan_ports(self):
        """Scan target for open ports and services."""
        print(f"Scanning {self.target} for open ports...")
        self.nm.scan(self.target, self.ports, arguments="-sV")
        results = []
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    state = self.nm[host][proto][port]['state']
                    if state == 'open':
                        service = self.nm[host][proto][port].get('name', 'unknown')
                        version = self.nm[host][proto][port].get('version', 'unknown')
                        results.append({
                            'port': port,
                            'service': service,
                            'version': version
                        })
        return results

    def check_vulnerabilities(self, service, version):
        """Query NVD API for vulnerabilities based on service and version."""
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        query = f"{service} {version}"
        params = {"keywordSearch": query}
        try:
            response = requests.get(base_url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get('vulnerabilities', [])
                for vuln in vulns:
                    cve_id = vuln['cve']['id']
                    description = vuln['cve']['descriptions'][0]['value']
                    self.vulnerabilities.append({
                        'cve_id': cve_id,
                        'description': description,
                        'service': service,
                        'version': version
                    })
        except requests.RequestException as e:
            print(f"Error querying NVD API: {e}")

    def generate_report(self):
        """Generate a report of findings."""
        report = f"Vulnerability Assessment Report - {self.target}\n"
        report += f"Generated on: {datetime.now()}\n\n"
        report += "Open Ports and Services:\n"
        for result in self.scan_results:
            report += f"Port {result['port']}: {result['service']} (Version: {result['version']})\n"
        report += "\nPotential Vulnerabilities:\n"
        if not self.vulnerabilities:
            report += "No vulnerabilities found.\n"
        else:
            for vuln in self.vulnerabilities:
                report += f"CVE ID: {vuln['cve_id']}\n"
                report += f"Service: {vuln['service']} (Version: {vuln['version']})\n"
                report += f"Description: {vuln['description']}\n\n"
        return report

    def run(self):
        """Run the vulnerability scanner."""
        self.scan_results = self.scan_ports()
        for result in self.scan_results:
            if result['version'] != 'unknown':
                self.check_vulnerabilities(result['service'], result['version'])
        report = self.generate_report()
        print(report)
        with open(f"report_{self.target}.txt", "w") as f:
            f.write(report)

if __name__ == "__main__":
    target = input("Enter target IP or hostname: ")
    scanner = VulnerabilityScanner(target)
    scanner.run()