# Credits

Original Scraper by Danny Chrastil (@DisK0nn3cT): https://github.com/DisK0nn3cT/linkedin-gatherer

Modified by @vysecurity

# Requirements
```
pip install -r requirements.txt
```

# Change Log

[v0.1 BETA 12-07-2017]
Additions:
* UI Updates
* Constrain to company filters
* Addition of Hunter for e-mail prediction

[v0.2 BETA 06-10-2022]
* Ported to Python 3
* Added requirements.txt
* Refactored the code to a re-usable class and modularised the arg parsing
* Options are now given on the command line so that it can be run without a user present
* Fixed a bug in paging calculation that caused a 403
* Removed Location field as it's not exposed by the API
* Added LinkedIn ID field
* Added a 'cookies' module which can be used to bypass Captcha by first logging in with Chrome and then dumping cookies (Windows only)
* Added option to supply a verification code if one is required on login (when --interative is used)
* Make email validation optional
* Optionally provide custom user-agent

# To-Do List

* Allow for horizontal scraping and mass automated company domain, and format prediction per company
* Add Natural Language Processing techniques on titles to discover groups of similar titles to be stuck into same "department". This should then be visualised in a graph.
* Add a cookie dumper for Linux/macOS and support Microsoft Edge

# Usage

Put in LinkedIn credentials in LinkedInt.py
Put Hunter.io API key in LinkedInt.py
Run LinkedInt.py and follow instructions

# Usage

## Options

```
>python LinkedInt.py -h
██╗     ██╗███╗   ██╗██╗  ██╗███████╗██████╗ ██╗███╗   ██╗████████╗
██║     ██║████╗  ██║██║ ██╔╝██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝
██║     ██║██╔██╗ ██║█████╔╝ █████╗  ██║  ██║██║██╔██╗ ██║   ██║
██║     ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║  ██║██║██║╚██╗██║   ██║
███████╗██║██║ ╚████║██║  ██╗███████╗██████╔╝██║██║ ╚████║   ██║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝

Providing you with Linkedin Intelligence
Author: Vincent Yiu (@vysec, @vysecurity)
Original version by @DisK0nn3cT
usage: LinkedInt.py [-h] {scrape,cookies} ...

Discovery LinkedIn

optional arguments:
  -h, --help        show this help message and exit

module:
  {scrape,cookies}
    scrape          Scrape LinkedIn for a target company or keyword
    cookies         Extracts LinkedIn Cookies from Chrome for use with this script.

-- SNIP --

usage: LinkedInt.py cookies [-h] -o OUTPUT

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file (do not include extentions)
-- SNIP --

usage: LinkedInt.py scrape [-h] [-u USERNAME] [-p PASSWORD] [-c COOKIES] [-a API_KEY] -s SEARCH [-b | --by-company | --no-by-company] [-v | --validate | --no-validate] [-i COMPANY_ID] --suffix SUFFIX
                           [--prefix {auto,full,firstlast,firstmlast,flast,first,first.last,fmlast,lastfirst}] -o OUTPUT [--user-agent USER_AGENT] [--interactive | --no-interactive]

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
  -c COOKIES, --cookies COOKIES
                        Cookie file to use (dump with cookies module)
  -a API_KEY, --api-key API_KEY
                        Hunter API Key
  -s SEARCH, --search SEARCH
                        Search Keywords (use quotes for more percise results)
  -b, --by-company, --no-by-company
                        Filter by Company
  -v, --validate, --no-validate
                        Validate e-mails
  -i COMPANY_ID, --company-id COMPANY_ID
                        Company ID
  --suffix SUFFIX       Suffix for e-mail generation (e.g. example.com)
  --prefix {auto,full,firstlast,firstmlast,flast,first,first.last,fmlast,lastfirst}
                        Prefix for e-mail generation
  -o OUTPUT, --output OUTPUT
                        Output file (do not include extentions)
  --user-agent USER_AGENT
                        Custom User-Agent
  --interactive, --no-interactive
                        Interactive prompt

```

## Example

The following example shows how to first dump your LinkedIn cookies from Chrome and then use them to carry out a search.

First we need to log in to LinkedIn using Chrome (on Windows). Then we run the following:

```
> python .\LinkedInt.py cookies -o cookies
██╗     ██╗███╗   ██╗██╗  ██╗███████╗██████╗ ██╗███╗   ██╗████████╗
██║     ██║████╗  ██║██║ ██╔╝██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝
██║     ██║██╔██╗ ██║█████╔╝ █████╗  ██║  ██║██║██╔██╗ ██║   ██║
██║     ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║  ██║██║██║╚██╗██║   ██║
███████╗██║██║ ╚████║██║  ██╗███████╗██████╔╝██║██║ ╚████║   ██║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝

Providing you with Linkedin Intelligence
Author: Vincent Yiu (@vysec, @vysecurity)
Original version by @DisK0nn3cT
[+] Cookie dump success. Saved to cookies.json
```

Now we can load the cookies into `LinkedInt` and carry out a search:

```
> python .\LinkedInt.py scrape -o example --no-validate -s "Example Company" --by-company --prefix "first.last" --suffix example.com --cookies .\cookies.json
██╗     ██╗███╗   ██╗██╗  ██╗███████╗██████╗ ██╗███╗   ██╗████████╗
██║     ██║████╗  ██║██║ ██╔╝██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝
██║     ██║██╔██╗ ██║█████╔╝ █████╗  ██║  ██║██║██╔██╗ ██║   ██║
██║     ██║██║╚██╗██║██╔═██╗ ██╔══╝  ██║  ██║██║██║╚██╗██║   ██║
███████╗██║██║ ╚████║██║  ██╗███████╗██████╔╝██║██║ ╚████║   ██║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝

Providing you with Linkedin Intelligence
Author: Vincent Yiu (@vysec, @vysecurity)
Original version by @DisK0nn3cT
[*] Loading cookie file: .\cookies.json
[+] Auth success
[Notice] Found company ID: 123456
[Notice] Found company ID: 789012
[Notice] Found company ID: 987654
[*] Using company ID: 123456
[*] 1002153 Results Found
[*] LinkedIn only allows 1000 results. Refine keywords to capture all data
[*] Fetching 25 Pages
[*] Fetching page 1 with 40 results
```
