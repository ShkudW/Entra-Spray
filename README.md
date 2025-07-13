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

![image](https://github.com/user-attachments/assets/baa14085-3a35-4274-92ed-71f0128bf0d8)

![image](https://github.com/user-attachments/assets/2980cfe7-a85e-4b4a-9e27-6b0f17846704)

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

