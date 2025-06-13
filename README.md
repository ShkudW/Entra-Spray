# Entra-Spray
Python tool that allows you to perform Password Spray and User Enumeration tests against Azure AD (Entra ID), in the Microsoft login service (login.microsoftonline.com).

The tool recreates the real Microsoft login flow to check:
1. Whether a user exists in Entra ID
2. Whether the password is correct
3. Whether there is a reference to a Federated Domain where passwords cannot be checked

✨ Main capabilities
✅ User existence check (-check)
✅ Password Spray with a list of users and passwords
✅ Full use of cookies, flowToken, canary and ctx to simulate a legitimate login
✅ Color printing and logging of results to the valid-users.txt file

```python
Entra-Spray.py [-h] -user username@doamin.com | path-to-usernames-file -pass password | path-to-passwords-file  [-check]
```




