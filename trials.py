import urllib.parse
import urllib.request
import re
import requests
import pprint
from bs4 import BeautifulSoup
from six.moves import urllib
import re

url = input('enter url you wish to test')
# url_visit = urllib.request.urlopen(url)
req = urllib.request.Request(url)
#Response is stored here
res = urllib.request.urlopen(req)
resp = res.read()
soup = BeautifulSoup(resp, "html.parser")
result=soup.find_all("form")
#re part to get URL in variable login_url
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246',
            'origin':url,
            'referer':url+'/cgi-bin/login.pl', #login_url
            }
#add fields extracted from form as keys to the payload dist, call injection func to inject malicious code as value into payload dist
payload = {
'access': 212321, 
'password': 'mypasswd',
'softvulnsec': '016',
'matnr': 9130300,
'login': 'Login',
}

s = requests.session()
#request = s.get(url)
response = s.post(url,headers=headers, data=payload)
print(response.status_code)
pprint.pprint(response.content)



# #print(url_visit.read())
# headers = {}
# headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
# req = urllib.request.Request(url,headers=headers)
# resp = urllib.request.urlopen(req)
# respData = resp.read()
# para = re.findall(r'<p>(.*?)</p>',str(respData))

# for each in para:
#     print(each)
# print(respData)

# try: 
#     x = urllib.request.urlopen(url)
#     print(x.read())
# except Exception as e:
#     print(str(e))

# try : 
#     headers = {}
#     headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246'
#     req = urllib.request.Request(url, headers=headers)
#     resp = urllib.request.urlopen(req)
#     respData = resp.read()
#     saveFile = open('withHeaders.txt','w')
#     saveFile.write(str(respData))
#     saveFile.close()

# except Exception as e:
#     print(str(e))
