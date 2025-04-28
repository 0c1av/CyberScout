#!!!THIS IS AN OUTDATED VERSION OF README.md!!!

# CyberScout
The CyberScout is a Python tool for directory and URL enumeration. It uses a wordlist to discover hidden paths on a target website, reporting results like "found", "not found", or "forbidden". It supports proxies, basic authentication, and customizable timeouts, making it ideal for penetration testing.

## Features
- Directory Enumeration: Discover hidden URLs by testing paths from a wordlist.
- Proxy Support: Option to route requests through an HTTP/HTTPS proxy.
- Basic Authentication: Supports basic authentication for protected directories.
- Timeout Handling: Configurable timeout settings to handle slow connections.
- Custom Output: Results can be saved to a file for later review.
- Advice: The tool provides recommendations based on results (e.g., using a proxy, increasing timeout, or using authentication).
- Method: Choose the method you want to use for the requests(GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)

## Getting Started
## Prerequisites
- Python 3.x installed on your machine
- Optional: A Proxy to route the requests through (e.g., for anonymity or geo-testing).

## Installation and Setup
git clone https://github.com/0c1av/CyberScout.git
cd CyberScout
pip install -r requirements.txt

## Usage
1. Run CyberScout: You can use CyberScout by specifying the target URL and a wordlist: python dirhunter.py -u https://example.com -w /path/to/wordlist.txt
Optional flags:
- -t: Set a custom timeout for HTTP requests (default: 5 seconds).
- -x: Use a built-in proxy, or import proxy in format ip:port.
- -a: Provide basic authentication credentials in the format username:password.
- -o: Save the results to a file.
- -m: Method to use (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)
2. Example: To run CyberScout with a proxy and save the results to a file:
  python dirhunter.py -u https://example.com -p /path/to/wordlist.txt -x 127.0.0.1:8080 -o results.txt

## Example Output
[FOUND] https://example.com/admin

[NOT FOUND] https://example.com/notfound

[FORBIDDEN] https://example.com/private

[TIMEOUT] https://example.com/slowpath

## Notes
- If the server is protected with basic authentication, provide the credentials with the -a flag.
- Use the -x flag to specify an HTTP or HTTPS proxy.

## Security Considerations
- Penetration Testing: Only use this tool on websites you have permission to test.
- Proxy Usage: Ensure the proxy you are using supports both HTTP and HTTPS protocols if needed.
