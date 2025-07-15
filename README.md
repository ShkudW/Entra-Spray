# Entra-Spray
Python tool that allows you to perform Password Spray and User Enumeration tests against Entra ID, with Microsoft login service (login.microsoftonline.com).

The tool recreates the real Microsoft login flow to check:
1. Whether a user exists in Entra ID
2. Whether the password is correct
3. Whether there is a reference to a Federated server

## Main capabilities:
-  Argument (-Check) for checking if user identity exsit in Tenant (after muliple requests it might be False Positive)
-  Argument (-ProxyTor) for route all traffic vit TOR (renew ip after every 7 min..) - This feature comes to solve the problem of False Positive
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

Checking If User Exist:
```python
python3 Entra-Spray.py -user list-of-usernames.txt -check

[✗] Username: shoshi@mytenant.onmicrosoft.com is exists
[✗] Username: david@mytenant.onmicrosoft.com is exists
[✗] Username: normuser@mytenant.onmicrosoft.com is exists
[✗] Username: shakedwiessman@mytenant.onmicrosoft.com is exists


----------------------------
 Valid users and successful authentications written to valid-users.txt
```
<img width="1374" height="164" alt="image" src="https://github.com/user-attachments/assets/54f20eec-2899-429d-9e6b-12c3f5703744" />

Checking If User Exist with TOR routing (-proxytor flag):
```python
python3 Entra-Spray.py -user list-of-usernames.txt -check -proxytor
```
<img width="1165" height="171" alt="image" src="https://github.com/user-attachments/assets/eb224b87-ab49-4b8f-9f84-0d3d11ab211c" />

Preforming Password Spray Attack:
```python
python3 Entra-Spray.py -user list-of-usernames.txt -password 'Aa123456' 
```
<img width="1323" height="155" alt="image" src="https://github.com/user-attachments/assets/b507524c-e681-4a31-bd63-366dad4f8e4e" />

Preforming Password Spray Attack with '-check' flag:
```python
python3 Entra-Spray.py -user list-of-usernames.txt -password 'Aa123456' -check
```
<img width="1348" height="146" alt="image" src="https://github.com/user-attachments/assets/d4c33afb-92b5-47d6-ba85-62f5c84f5c8b" />


Preforming Password Spray Attack with '-check' flag and with TOR routing:

The script will check if:
- The user is required to have MFA but has not yet set it up
- The user is required to have MFA
- The user is required to change their password
- 
```python
python3 Entra-Spray.py -user list-of-usernames.txt -password 'Aa123456' -check -proxytor
```
<img width="1397" height="158" alt="image" src="https://github.com/user-attachments/assets/09b80662-a916-4701-8a37-acad264e5425" />

<img width="1404" height="164" alt="image" src="https://github.com/user-attachments/assets/630588b2-bba4-498d-8e02-833f8ad6d3f7" />

<img width="1374" height="164" alt="image" src="https://github.com/user-attachments/assets/681ab882-dbbe-41d0-8944-248fe43ac764" />


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

