Automated Web Application Vulnerability Scanner

This Python script automates web application vulnerability scanning by performing tests for common vulnerabilities such as SQL injection, cross-site scripting (XSS), cross-site request forgery (CSRF), file inclusion, directory traversal, command injection, authentication bypass, broken access controls, server-side request forgery, insecure direct object reference (IDOR), injection flaws, information disclosure, and insufficient logging and monitoring.
Installation

To install the script, clone the repository to your local machine:
bash
git clone https://github.com/HackGroot/webapp-vuln-scanner.py

The script requires the requests module to be installed. You can install it using pip:
pip install requests

Usage

To use the script, specify the URL of the target web application as a command-line argument:

python webapp-vuln-scanner.py -u http://example.com

The script will then send HTTP requests to the application and analyze the responses to determine if any of the tested vulnerabilities are present. The results will be printed in a report indicating which vulnerabilities were found to be present or absent in the application.

Customization
The script can be customized by adding or removing tests as needed to suit specific requirements. Simply modify the vulnerabilities list in the script to include the desired tests.

Contributions
Contributions to the script are welcome. If you find a bug or have an idea for a new feature, feel free to open an issue or submit a pull request.


