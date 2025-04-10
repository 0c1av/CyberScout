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
		forbidden_freq = forbidden_freq +1

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

	if advice_list:
		for advice in advice_list:
			print(f"{YELLOW}---{advice}---{RESET}")

	#if not timeout_freq and not forbidden_freq and not found_freq and not error_freq:
	#	print("No value for frequenties")


def check_path(url, path, method, timeout, auth, proxies, output_file, found_list, proxy_option, start_time):
	global should_stop

	path = path.strip()
	full_url = f"{url}/{path}"
	result = ""

	if should_stop:
		return

	try:
		if method.lower() in valid_methods:
			response = getattr(requests, method.lower())(full_url, timeout=timeout, auth=auth, proxies=proxies)
		else:
			print(f"{RED}[ERROR]{RESET} Invalid method")
			sys.exit()
		if response.status_code == 200:
			result = f"{GREEN}[FOUND]{RESET} {full_url}"
			timeout_status = False
			forbidden_status = False
			found_status = True
			error_status = False
			shared_data["found_list"].append(full_url)
			if output_file:
				with open(output_file, 'r+') as file:
					content = file.readlines()
					for i, line in enumerate(content):
						if line.strip() == "========================================================":
							content.insert(i, f"{GREEN}[FOUND]{RESET} {full_url}\n")
							break
					file.seek(0)
					file.writelines(content)

		elif response.status_code == 404:
			result = f"[NOT FOUND] {full_url}"
			timeout_status = False
			forbidden_status = False
			found_status = False
			error_status = False

		elif response.status_code == 403:
			result = f"{D_GRAY}[FORBIDDEN]{RESET} {full_url}"
			timeout_status = False
			forbidden_status = True
			found_status = False
			error_status = False
		else:
			result = f"[{response.status_code}] {full_url}"
			timeout_status = False
			forbidden_status = False
			found_status = False
			error_status = False

	except requests.exceptions.Timeout:
		result = f"{L_GRAY}[TIMEOUT]{RESET} {full_url}"
		timeout_status = True
		forbidden_status = False
		found_status = False
		error_status = False

	except requests.exceptions.RequestException as e:
		result = f"{RED}[ERROR]{RESET} {full_url} -> {e}"
		timeout_status = False
		forbidden_status = False
		found_status = False
		error_status = True

	elapsed = time.time() - start_time
	minutes = int(elapsed // 60)
	seconds = int(elapsed % 60)

	if result != f"[NOT FOUND] {full_url}":
		print(f"{minutes:02d}:{seconds:02d} - {result}")
	if output_file:
		with open(output_file, 'a') as file:
			file.write(f"{result}\n")

	'''
	timeout_freq = timeout_calc(timeout_status, timeout_freq)
	forbidden_freq = forbidden_calc(forbidden_status, forbidden_freq)
	found_freq = found_calc(found_status, found_freq)
	error_freq = error_calc(error_status, error_freq)
	'''

	with data_lock:
		shared_data["timeout_freq"] = timeout_calc(timeout_status, shared_data["timeout_freq"])
		shared_data["forbidden_freq"] = forbidden_calc(forbidden_status, shared_data["forbidden_freq"])
		shared_data["found_freq"] = found_calc(found_status, shared_data["found_freq"])
		shared_data["error_freq"] = error_calc(error_status, shared_data["error_freq"])

	print(f"timeout: {shared_data['timeout_freq']}, forbidden: {shared_data['forbidden_freq']}, found: {shared_data['found_freq']}, error: {shared_data['error_freq']}")
	advice_calc(shared_data["timeout_freq"], shared_data["forbidden_freq"], shared_data["found_freq"], shared_data["error_freq"], proxy_option)

	return timeout_freq, forbidden_freq, found_freq, error_freq, found_list


#arguments
parser = argparse.ArgumentParser(description="Directory hunting tool for discovering URLs.")
parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g. https://example.com)")
parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path wordlist (e.g. common.txt)")
parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for requests in seconds")
parser.add_argument("-o", "--output", type=str, help="File to save the output (e.g. results.txt)")
parser.add_argument("-a", "--auth", type=str, help="Basic authentication in the format 'username:password'")
parser.add_argument("-x", "--proxy", nargs='?', const="built_in", help="Proxy to use in the format 'ip:port'. If omitted, a built-in proxy will be used.")
parser.add_argument("-m", "--method", type=str, default="GET", help="Method to use (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)")
args = parser.parse_args()

#colors
D_GRAY = "\033[90m"
L_GRAY = "\033[97m"
RED = "\033[31m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE_BACK = "\033[44m"
ORANGE = "\033[33m"
RESET = "\033[0m"

#basic variables
start_time = time.time()
should_stop = False
url = args.url
path_file = args.wordlist
if os.path.exists(path_file):
	pass
else:
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
#timeout_freq = 0
forbidden_status = False
#forbidden_freq = 0
found_status = False
#found_freq = 0
error_status = False
#error_freq = 0


shared_data = {
    "timeout_freq": 0,
    "forbidden_freq": 0,
    "found_freq": 0,
    "error_freq": 0,
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

#presentation
print("========================================================")
print(f"{BLUE_BACK}CYBERSCOUT{RESET} by 0c1av")
print("========================================================")
print(f"Url:        {url}")
print(f"Wordlist:   {path_file}")
print(f"Timeout:    {timeout}")
print(f"Proxy:      {proxies}")
print(f"Method:     {method.upper()}")
print("========================================================")
print(f"{current_time}: DirHunter launched by {user}")
print("========================================================")
print("")


#Trying paths
if output_file is not None:
	with open(output_file, 'w') as file:
		file.write("========================================================\n")


with open(path_file, 'r') as file:
	paths_list = file.readlines()

found_list = []

try:
	with ThreadPoolExecutor(max_workers=10) as executor:
		futures = []
		for path in paths_list:
			futures.append(executor.submit(check_path, url, path, method, timeout, auth, proxies, output_file, found_list, proxy_option, start_time))
		for future in futures:
			future.result()
	print("========================================================")
	print("Found URLs:\n")
	for found in shared_data["found_list"]:
		print(found)

except KeyboardInterrupt:
	print("Keyborad interrumpt\n")

	executor.shutdown(wait=False, cancel_futures=True)
	should_stop = True

	print("========================================================\n")
	print("Found URLs:")
	for found in shared_data["found_list"]:
		print(found)
	sys.exit(0)
