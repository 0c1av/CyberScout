import os
import requests
import threading
import argparse
from requests.auth import HTTPBasicAuth
from datetime import datetime
import subprocess

parser = argparse.ArgumentParser(description="Directory hunting tool for discovering URLs.")
parser.add_argument("-u", "--url", type=str, required=True, help="Target URL (e.g. https://example.com)")
parser.add_argument("-w", "--wordlist", type=str, required=True, help="Path wordlist (e.g. common.txt)")
parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for requests in seconds")
parser.add_argument("-o", "--output", type=str, help="File to save the output (e.g. results.txt)")
parser.add_argument("-a", "--auth", type=str, help="Basic authentication in the format 'username:password'")
parser.add_argument("-x", "--proxy", type=str, help="Proxy to use in the format 'ip:port'")
args = parser.parse_args()

D_GRAY = "\033[90m"
L_GRAY = "\033[97m"
RED = "\033[31m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE_BACK = "\033[44m"
RESET = "\033[0m"

url = args.url
path_file = args.wordlist
timeout = args.timeout
output_file = args.output

auth = None
if args.auth:
	username, password = args.auth.split(":")
	auth = HTTPBasicAuth(username, password)

timeout_status = False
timeout_freq = 0
forbidden_status = False
forbidden_freq = 0

proxy_option = False
proxies = {}
if args.proxy:
	proxy_option = True
	proxy = args.proxy
	if url.startswith("https://"):
		proxies = {"https": f"https://{proxy}"}
	else:
		proxies = {"http": f"http://{proxy}"}

current_time = datetime.now()
formatted_time = current_time.strftime('%Y/%m/%d %H:%M:%S')
user = subprocess.getoutput("whoami")

print("========================================================")
print(f"{BLUE_BACK}CYBERSCOUT{RESET} by 0c1av")
print("========================================================")
print(f"Url:        {url}")
print(f"Wordlist:   {path_file}")
print(f"Timeout:    {timeout}")
print("========================================================")
print(f"{current_time}: DirHunter launched by {user}")
print("========================================================")
print("")

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


def advice_calc(timeout_freq, forbidden_freq, proxy_option):
	advice_list = []

	#timeout
	if timeout_freq > 2:
		advice_list.append("Try increasing the timeout")
	if proxy_option == False:
		if timeout_freq > 4:
			advice_list.append("Try using a proxy")
	#forbidden
	if forbidden_status > 1:
		advice_list.append("Try using authentication")

	if advice_list:
		for advice in advice_list:
			print(f"{YELLOW}---{advice}---{RESET}")

if output_file:
	output_handle = open(output_file, 'w')

with open(path_file, 'r') as file:
	paths_list = file.readlines()

for path in paths_list:
	path = path.strip()
	full_url = f"{url}/{path}"
	try:
		response = requests.get(full_url, timeout=timeout, auth=auth, proxies=proxies)
		if response.status_code == 200:
			result = f"{GREEN}[FOUND]{RESET} {full_url}"
			timeout_status = False
			forbidden_status = False
		elif response.status_code == 404:
			result = f"[NOT FOUND] {full_url}"
			timeout_status = False
			forbidden_status = False
		elif response.status_code == 403:
			result = f"{D_GRAY}[FORBIDDEN]{RESET} {full_url}"
			timeout_status = False
			forbidden_status = True
		else:
			result = f"[{response.status_code}] {full_url}"
			timeout_status = False
			forbidden_status = False

	except requests.exceptions.Timeout:
		result = f"{L_GRAY}[TIMEOUT]{RESET} {full_url}"
		timeout_status = True
		forbidden_status = False

	except requests.exceptions.RequestException as e:
		result = f"{RED}[ERROR]{RESET} {full_url} -> {e}"
		timeout_status = False
		forbidden_status = False

	print(result)

	if output_file:
		output_handle.write(result + '\n')
	timeout_freq = timeout_calc(timeout_status, timeout_freq)
	forbidden_freq = forbidden_calc(forbidden_status, forbidden_freq)
	advice_calc(timeout_freq, forbidden_freq, proxy_option)
	#print(f"timeout_freq: {timeout_freq}, forbidden_freq: {forbidden_freq}")


if output_file:
	output_handle.close()
