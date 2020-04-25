import requests

url = "http://140.113.207.246/login.php"
session = requests.Session()
#r = session.get(url)
#print(r.text)
payload = {'usr':'CS2020','pwd':'cs2020','btn_login':'Login'}
r = session.post(url,data = payload)
