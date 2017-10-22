# Parse JSON results and guess departments


#!/usr/bin/python
import json, argparse, re, collections

parser = argparse.ArgumentParser(description='LinedInt output parser')
parser.add_argument('-i', '--infile', help='Keywords to search')
args = parser.parse_args()

with open(args.infile) as data_file:    
    data = json.load(data_file)

groups = collections.OrderedDict([
  ('C Level', ['chief executive', r'(\W|^)C[A-Z]O(\W|$)']),
  ('HR', ['recruitment']),
  ('Sales and Marketing', ['accounts? manager','sales','marketing']),
  ('Delivery', ['analyst', 'consultant','technician','developer','programmer','tester','assurance']),
  ('Administrative', ['project manager','project delivery','receptionist',r'assistant','^PA ']),
  ('Directors', ['director'])
])

categorised = {}

print 'Search: ' + data['search']

for d in data['results']:
  category = None
  occ = re.sub(' at ' + data['search'] + '.*', '', d['occupation'])
  for groupname, g in groups.iteritems():
    if category: continue
    for regex in g:
      if category: continue
      if re.search( regex, occ, re.IGNORECASE ):
        print d['name'] + ' is in ' + groupname + ' ('+regex+') "'+occ+'"'
        category = groupname
  if not category:
    category = 'Unknown'
  
  if not category in categorised.keys():
    categorised[category] = []

  categorised[category].append(d)

keys = groups.keys()
keys.append('Unknown')
for g in keys:
  if g not in categorised.keys(): continue
  people = categorised[g]
  print ''
  print '\033[1m' + g + '\033[0m'
  for p in people:
    print p['name']

