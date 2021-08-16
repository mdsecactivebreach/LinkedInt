#!/usr/bin/python3

# LinkedInt
# Scrapes LinkedIn without using LinkedIn API
# Original scraper by @DisK0nn3cT (https://github.com/DisK0nn3cT/linkedin-gatherer)
# Modified by @vysecurity
# - Additions:
# --- UI Updates
# --- Constrain to company filters
# --- Addition of Hunter for e-mail prediction




import sys
import re
import time
import requests
import subprocess
import json
import argparse

import os
import urllib.request, urllib.parse, urllib.error
import math
import string
from bs4 import BeautifulSoup

import csv as csv_module
import pdb
import ssl
import importlib
from requests.packages.urllib3.exceptions import InsecureRequestWarning



""" Setup Argument Parameters """
parser = argparse.ArgumentParser(description='Discovery LinkedIn')
parser.add_argument('-u', '--keywords', help='Keywords to search')
parser.add_argument('-o', '--output', help='Output file (do not include extentions)')
parser.add_argument('-e', '--email', help='Domain used for email address')
parser.add_argument('-c', '--company', help='Restrict to company filter', action="store_true")
parser.add_argument('-i', '--id', help='Company ID to use')
parser.add_argument('-f', '--format', help='Email format. "auto" to search Hunter')
parser.add_argument('--login', help="Login for LinkedIn", required=True)
parser.add_argument('--password', help="Password for LinkedIn", required=True)
parser.add_argument('--apikey', help="API Key for HunterIO", required=True)

args = parser.parse_args()

api_key = args.apikey # Hunter API key
username = args.login # enter username here
password = args.password   # enter password here
proxies = {} #{'https':'127.0.0.1:8080'}
# silence all url warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def login():
    # cookie_filename = "cookies.txt"

    # pdb.set_trace()
    # cookiejar = http.cookiejar.MozillaCookieJar(cookie_filename)
    # opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(),urllib.request.HTTPHandler(debuglevel=0),urllib.request.HTTPSHandler(debuglevel=0),urllib.request.HTTPCookieProcessor(cookiejar))
    # # page = loadPage(opener, "https://www.linkedin.com/")
    # # pdb.set_trace()
    # # parse = BeautifulSoup(page, "html.parser")

    # # # csrf = parse.find(id="loginCsrfParam-login")['value']
    # # csrf = cookiejar._cookies['.linkedin.com']['/']['bcookie'].value.split('&')[1]

    # # login_data = urllib.urlencode({'session_key': username, 'session_password': password, 'loginCsrfParam': csrf})
    # # page = loadPage(opener,"https://www.linkedin.com/uas/login-submit", login_data)
    
    # page = loadPage(opener, "https://www.linkedin.com/uas/login")
    # parse = BeautifulSoup(page, "html.parser")
    # #csrf = parse.find(id="loginCsrfParam")['value']
    # for link in parse.find_all('input'):
    #         name = link.get('name')
    #         if name == 'loginCsrfParam':
    #                 csrf = link.get('value')

    # login_data = urllib.parse.urlencode({'session_key': username, 'session_password': password, 'loginCsrfParam': csrf})
    # page = loadPage(opener,"https://www.linkedin.com/checkpoint/lg/login-submit", login_data)

    # parse = BeautifulSoup(page, "html.parser")
    # cookie = ""
    
    s = requests.Session()
    res = s.get('https://www.linkedin.com/uas/login')
    csrf = res.text.split('loginCsrfParam" value="')[1].split('"')[0]
    
    
    # data = res.text[res.text.find("<form"):res.text.find("</form")]

    login_data = {}

    # for c in data.split('input type')[1:]:
    #     login_data[c.split('name="')[1].split('"')[0]] = c.split('value="')[1].split('"')[0] 

    login_data['session_key'] = username
    login_data['session_password'] = password

    login_data['loginCsrfParam'] = csrf
    res = s.post('https://www.linkedin.com/checkpoint/lg/login-submit', data=login_data)


    
    return s.cookies['li_at']

def loadPage(client, url, data=None):
    try:
        response = client.open(url)
    except:
        print("[!] Cannot load main LinkedIn page")
    try:
        if data is not None:
            response = client.open(url, data)
        else:
            response = client.open(url)
        return ''.join(response.readlines())
    except:
        sys.exit(0)

def get_search():

    body = ""
    csv = []
    css = """<style>
    #employees {
        font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
        border-collapse: collapse;
        width: 100%;
    }

    #employees td, #employees th {
        border: 1px solid #ddd;
        padding: 8px;
    }

    #employees tr:nth-child(even){background-color: #f2f2f2;}

    #employees tr:hover {background-color: #ddd;}

    #employees th {
        padding-top: 12px;
        padding-bottom: 12px;
        text-align: left;
        background-color: #4CAF50;
        color: white;
    }
    </style>

    """

    header = """<center><table id=\"employees\">
             <tr>
             <th>Photo</th>
             <th>Name</th>
             <th>Possible Email:</th>
             <th>Job</th>
             <th>Location</th>
             </tr>
             """

    # Do we want to automatically get the company ID?


    if bCompany:
        if bAuto:
            # Automatic
            # Grab from the URL 
            companyID = 0
            url = "https://www.linkedin.com/voyager/api/typeahead/hits?q=blended&query=%s" % search
            headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
            cookies['JSESSIONID'] = 'ajax:0397788525211216808'
            r = requests.get(url, cookies=cookies, headers=headers)
            content = json.loads(r.text)
            firstID = 0
            for i in range(0,len(content['elements'])):
                try:
                    companyID = content['elements'][i]['hitInfo']['com.linkedin.voyager.typeahead.TypeaheadCompany']['id']
                    if firstID == 0:
                        firstID = companyID
                    print("[Notice] Found company ID: %s" % companyID)
                except:
                    continue
            companyID = firstID
            if companyID == 0:
                print("[WARNING] No valid company ID found in auto, please restart and find your own")
        else:
            # Don't auto, use the specified ID
            companyID = bSpecific

        print()
        
        print("[*] Using company ID: %s" % companyID)

    # Fetch the initial page to get results/page counts
    
    if bCompany == False:
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=0" % search
    else:
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s,title->%s)&origin=OTHER&q=guided&start=0" % (companyID, search)
    
    # url = urllib.parse.quote(url)
    # print(url)
    
    headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
    cookies['JSESSIONID'] = 'ajax:0397788525211216808'
    #print url
    # s = requests.Session()
    # req = requests.Request(method="GET", url="https://www.linkedin.com")
    # prep = req.prepare()
    # prep.url = url

    r = requests.get(url, cookies=cookies, headers=headers, verify=False)
    content = json.loads(r.text)
    # pdb.set_trace()
    data_total = content['elements'][0]['total']

    # Calculate pages off final results at 40 results/page
    pages = int(data_total / 40) + 1

    if pages == 0:
        pages = 1

    if data_total % 40 == 0:
        # Becuase we count 0... Subtract a page if there are no left over results on the last page
        pages = pages - 1 

    if pages == 0: 
        print("[!] Try to use quotes in the search name")
        sys.exit(0)
    
    print("[*] %i Results Found" % data_total)
    if data_total > 1000:
        pages = 25
        print("[*] LinkedIn only allows 1000 results. Refine keywords to capture all data")
    print("[*] Fetching %i Pages" % pages)
    print()
    csvfile = open('{}.csv'.format(outfile), 'w')
    csvwriter = csv_module.writer(csvfile, delimiter=',', quotechar='"', quoting=csv_module.QUOTE_MINIMAL)
    
    for p in range(pages):
        # Request results for each page using the start offset
        if bCompany == False:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List()&keywords=%s&origin=OTHER&q=guided&start=%i" % (search, p*40)
        else:
            url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s,title->%s)&origin=OTHER&q=guided&start=%i" % (companyID, search, p*40)
        #print url
        r = requests.get(url, cookies=cookies, headers=headers, verify=False, proxies=proxies)
        content = r.text.encode('UTF-8')
        content = json.loads(content)
        print("[*] Fetching page %i with %i results" % ((p),len(content['elements'][0]['elements'])))
        for c in content['elements'][0]['elements']:
            
            if 'com.linkedin.voyager.search.SearchProfile' in c['hitInfo'] and c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['headless'] == False:
                try:
                    data_industry = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['industry']
                except:
                    data_industry = ""    
                data_firstname = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['firstName']
                data_lastname = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['lastName']
                data_slug = "https://www.linkedin.com/in/%s" % c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['publicIdentifier']
                data_occupation = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['occupation']
                try:
                    data_location = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['location']
                except:
                    data_location = ""
                # pdb.set_trace()
                try:
                    data_picture = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.common.VectorImage']['rootUrl'] + [d['fileIdentifyingUrlPathSegment'] for d in c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.common.VectorImage']['artifacts'] if '400' in d['fileIdentifyingUrlPathSegment']][0]
                except:
                    print("[*] No picture found for %s %s, %s" % (data_firstname, data_lastname, data_occupation))
                    data_picture = ""

                # incase the last name is multi part, we will split it down
                # Also trying to strip out anything after a comma, and any
                # word that is all caps, since those are probably certs
                # (CPA, CFA, CISSP, etc, etc, etc)

                parts = []
                for p in data_lastname.split(',')[0].split(' '):
                    if p.upper() != p:
                        parts.append(p)

                name = data_firstname + " " + data_lastname
                fname = ""
                mname = ""
                lname = ""

                if len(parts) == 1:
                    fname = data_firstname.split(' ')[0]
                    mname = '?'
                    lname = parts[0]
                elif len(parts) == 2:
                    fname = data_firstname.split(' ')[0]
                    mname = parts[0]
                    lname = parts[1]
                elif len(parts) >= 3:
                    fname = data_firstname.split(' ')[0]
                    lname = parts[0]
                else:
                    fname = data_firstname.split(' ')[0]
                    lname = '?'

                fname = re.sub('[^A-Za-z]+', '', fname)
                mname = re.sub('[^A-Za-z]+', '', mname)
                lname = re.sub('[^A-Za-z]+', '', lname)

                if len(fname) == 0 or len(lname) == 0:
                    # invalid user, let's move on, this person has a weird name
                    continue

                    #come here

                if prefix == 'full':
                    user = '{}{}{}'.format(fname, mname, lname)
                if prefix == 'firstlast':
                    user = '{}{}'.format(fname, lname)
                if prefix == 'firstmlast':
                    user = '{}{}{}'.format(fname, mname[0], lname)
                if prefix == 'flast':
                    user = '{}{}'.format(fname[0], lname)
                if prefix == 'first.last':
                    user = '{}.{}'.format(fname, lname)
                if prefix == 'fmlast':
                    user = '{}{}{}'.format(fname[0], mname[0], lname)
                if prefix == 'lastfirst':
                    user = '{}{}'.format(lname, fname)
                if prefix == 'first':
                    user = '{}'.format(fname)
                if prefix == 'firstl':
                    user = '{}{}'.format(fname, lname[0])
                    
                email = '{}@{}'.format(user, suffix)

                body += "<tr>" \
                    "<td><a href=\"%s\"><img src=\"%s\" width=200 height=200></a></td>" \
                    "<td><a href=\"%s\">%s</a></td>" \
                    "<td>%s</td>" \
                    "<td>%s</td>" \
                    "<td>%s</td>" \
                    "<a>" % (data_slug, data_picture, data_slug, name, email, data_occupation, data_location)
                
                csv.append('"%s","%s","%s","%s","%s", "%s"' % (data_firstname, data_lastname, name, email, data_occupation, data_location.replace(",",";")))
                foot = "</table></center>"
                f = open('{}.html'.format(outfile), 'w')
                f.write(css)
                f.write(header)
                f.write(body)
                f.write(foot)
                f.close()
                
                csvwriter.writerow([data_firstname, data_lastname, name, email, data_occupation, data_location.replace(",",";")])
                
                
            else:
                print("[!] Headless profile found. Skipping")
        print()
    csvfile.close()

def banner():
    print('''
        ██╗     ██╗███╗   ██╗██╗  ██╗███████╗██████╗ ██╗███╗   ██╗████████╗
██║     ██║████╗  ██║██║ ██╔╝██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝
██║     ██║██╔██╗ ██║█████╔╝ █████╗  ██║  ██║██║██╔██╗ ██║   ██║   
██║     ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║  ██║██║██║╚██╗██║   ██║   
███████╗██║██║ ╚████║██║  ██╗███████╗██████╔╝██║██║ ╚████║   ██║   
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   
'''       )                                                     

            # print("\033[1;31m%s\033[0;0m" % data)
            # print("\033[1;34mProviding you with Linkedin Intelligence")
            # print("\033[1;32mAuthor: Vincent Yiu (@vysec, @vysecurity)\033[0;0m")
            # print("\033[1;32mOriginal version by @DisK0nn3cT\033[0;0m")

def authenticate():
    try:
        a = login()
        session = a
        if len(session) == 0:
            sys.exit("[!] Unable to login to LinkedIn.com")
        print("[*] Obtained new session")
        cookies = dict(li_at=session)
    except Exception as e:
        sys.exit("[!] Could not authenticate to linkedin. %s" % e)
    return cookies

if __name__ == '__main__':
    banner()
    # Prompt user for data variables
    search = args.keywords if args.keywords!=None else input("[*] Enter search Keywords (use quotes for more precise results)\n")
    print() 
    outfile = args.output if args.output!=None else input("[*] Enter filename for output (exclude file extension)\n")
    print() 
    
    while True:
        if args.company:
            bCompany = "y"
            args.company = None
        else:
            bCompany = input("[*] Filter by Company? (Y/N): \n")
        if bCompany.lower() == "y" or bCompany.lower() == "n":
            break
        else:
            print("[!] Incorrect choice")

    if bCompany.lower() == "y":
        bCompany = True
    else:
        bCompany = False

    bAuto = True
    bSpecific = 0
    prefix = ""
    suffix = ""

    print()

    if bCompany:
        while True:
            if args.id:
                if args.id == "auto":
                    bSpecific = ""
                else:
                    bSpecific = args.id
                args.id = None
            else:
                bSpecific = input("[*] Specify a Company ID (Provide ID or leave blank to automate): \n")
        
            if bSpecific != "":
                bAuto = False
                if bSpecific != 0:
                    try:
                        int(bSpecific)
                        break
                    except:
                        print("[!] Incorrect choice, the ID either has to be a number or blank")
                    
                else:
                    print("[!] Incorrect choice, the ID either has to be a number or blank")
            else:
                bAuto = True
                break

    print()

    
    while True:
        if args.email:
            suffix = args.email.lower()
            args.email = None
        else:
            suffix = input("[*] Enter e-mail domain suffix (eg. contoso.com): \n")
            suffix = suffix.lower()
        if "." in suffix:
            break
        else:
            print("[!] Incorrect e-mail? There's no dot")

    print()

    while True:
        if args.format:
            prefix = args.format.lower()
            args.format = None
        else:    
            prefix = input("[*] Select a prefix for e-mail generation (auto,full,firstlast,firstmlast,flast,first.last,fmlast,lastfirst): \n")
            prefix = prefix.lower()
        print()
        if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix =="first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst" or prefix == 'firstl':
            break
        elif prefix == "auto":
            #if auto prefix then we want to use hunter IO to find it.
            print("[*] Automaticly using Hunter IO to determine best Prefix")
            url = "https://hunter.io/trial/v2/domain-search?offset=0&domain=%s&format=json" % suffix
            r = requests.get(url)
            content = json.loads(r.text)
            if "status" in content:
                print("[!] Rate limited by Hunter IO trial")
                url = "https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s" % (suffix, api_key)
                #print url
                r = requests.get(url)
                content = json.loads(r.text)
                if "status" in content:
                    print("[!] Rate limited by Hunter IO Key")
                    continue
            #print content
            prefix = content['data']['pattern']
            print("[!] %s" % prefix)
            if prefix:
                prefix = prefix.replace("{","").replace("}", "")
                if prefix == "full" or prefix == "firstlast" or prefix == "firstmlast" or prefix == "flast" or prefix =="first" or prefix == "first.last" or prefix == "fmlast" or prefix == "lastfirst" or prefix == 'firstl':
                    print("[+] Found %s prefix" % prefix)
                    
                    break
                else:
                    print("[!] Automatic prefix search failed, please insert a manual choice")
                    continue
            else:
                print("[!] Automatic prefix search failed, please insert a manual choice")
                continue
        else:
            print("[!] Incorrect choice, please select a value from (auto,full,firstlast,firstmlast,flast,first.last,fmlast)")

    print() 


    
    # URL Encode for the querystring
    if bCompany:
        search = urllib.parse.quote(search)
    else:
        search = urllib.parse.quote_plus(search)
    cookies = authenticate()
  
    
    # Initialize Scraping
    get_search()

    print("[+] Complete")
