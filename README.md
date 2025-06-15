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

### Install:

```bash
pip install httpx
pip install httpx[http2]
pip install httpx[socks]
pip install stem
```

```python
Entra-Spray.py [-h] -user username@doamin.com | path-to-usernames-file -pass password | path-to-passwords-file  [-check] [-ProxyTor]
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
  ```

