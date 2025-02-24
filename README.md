# W25_4495_S1_JackieK

Development of an AI-Integrated Automated Scanning Tool for Security Analysis and Remediation


Name : Jackie Kim
Student ID : 300376300
Course : CSIS4495-001 Applied Research Project

Project Overview
The Automated Penetration Testing Tool is designed to scan an organization's website for potential security vulnerabilities. The tool performs various scanning tasks, including host discovery, port scanning, OS detection, vulnerability scanning, and code analysis. It generates an HTML report summarizing the scan results, highlighting the vulnerabilities, and suggesting remediation methods using an integrated AI tool.

This project aims to help organizations identify weaknesses in their web infrastructure and improve security through automated testing.

Features
Host Discovery: Identifies active and reachable target IP addresses and provides information about open ports, OS guesses, and traceroute data.
Web Enumeration: Scans for open HTTP and HTTPS ports, identifying services such as Cloudflare's HTTP proxy services.
DNS Enumeration: Uses DNS brute-forcing to identify subdomains of the target.
Vulnerability Scanning: Uses Nmap scripts to scan for HTTP title, headers, and methods.
Code Analysis: Integrates the Semgrep tool to scan for code vulnerabilities, highlighting those with a HIGH impact.
HTML Report: Generates a clickable HTML report containing detailed scan results for each command, with links to specific findings.
AI Integration: Uses an AI tool to analyze the generated report and provide remediation suggestions for identified vulnerabilities.

***To run the developed penetration testing scanning tool, please download the "pentesting" directory and follow the instructions provided in its README file.***
