#!/usr/local/bin/python3

# Home: https://github.com/cjenison/f5_bigip_inventory_reporter
# Author: Chad Jenison (c.jenison@f5.com)

import argparse
import sys
import requests
import getpass
import xlsxwriter
import json
import re
from ipaddress import ip_network

requests.packages.urllib3.disable_warnings()
contentJsonHeader = {'Content-Type': "application/json"}

parser = argparse.ArgumentParser(description='A tool to scan network looking for F5 BIG-IP Systems and then produce an XLSX Report File')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--networks', '-n', help='Network(s) to scan (only IPv4 supported) in format networkaddr/masklength', required=True, nargs='*')
#parser.add_argument('--outputfile', '-o', help='Filename for XLSX output', required=True)
parser.add_argument('--outputfile', '-o', help='Filename for XLSX output')
passwdoption = parser.add_mutually_exclusive_group()
passwdoption.add_argument('--password', '-p', help='Supply Password as command line argument \(dangerous due to shell history\)')
passwdoption.add_argument('--passfile', '-pf', help='Obtain password from a text file \(with password string as the only contents of file\)')

args= parser.parse_args()

def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
    authPost = authbip.post(authurl, headers=contentJsonHeader, data=json.dumps(payload))
    if authPost.status_code == 404:
        print ('attempt to obtain authentication token failed; will fall back to basic authentication; remote LDAP auth will require configuration of local user account')
        token = None
    elif authPost.status_code == 401:
        print ('attempt to obtain authentication token failed due to invalid credentials')
        token = 'Fail'
    elif authPost.json().get('token'):
        token = authPost.json()['token']['token']
        print ('Got Auth Token: %s' % (token))
    else:
        print ('Unexpected error attempting POST to get auth token')
        quit()
    return token

def get_bigip_info(bigip, username, password):
    bip = requests.session()
    bip.verify = False
    bigipData = {}
    token = get_auth_token(bigip, username, password)
    if token and token != 'Fail':
        bip.headers.update({'X-F5-Auth-Token': token})
    else:
        bip.auth = (username, password)
    versionRaw = bip.get('https://%s/mgmt/tm/sys/version/' % (bigip))
    if versionRaw.status_code == 401 or versionRaw.status_code == 404:
        if versionRaw.status_code == 401:
            print ('Couldn\'t Authenticate')
        else:
            print ('BIG-IP too old for iControl REST')
        bigipData['hostname'] = 'unknown'
        bigipData['serialNumber'] = 'unknown'
        bigipData['marketingName'] = 'unknown'
        bigipData['provisionedModules'] = 'unknown'
        bigipData['version'] = 'unknown'
    else:
        version = versionRaw.json()
        if version.get('nestedStats'):
            bigipData['version'] = version['entries']['https://localhost/mgmt/tm/sys/version/0']['nestedStats']['entries']['Version']['description']
        else:
            volumes = bip.get('https://%s/mgmt/tm/sys/software/volume' % (bigip)).json()
            for volume in volumes['items']:
                if volume.get('active'):
                    if volume['active'] == True:
                        bigipData['version'] = volume['version']
        hardware = bip.get('https://%s/mgmt/tm/sys/hardware/' % (bigip)).json()
        bigipData['serialNumber'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/system-info']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/system-info/0']['nestedStats']['entries']['bigipChassisSerialNum']['description']
        bigipData['marketingName'] = hardware['entries']['https://localhost/mgmt/tm/sys/hardware/platform']['nestedStats']['entries']['https://localhost/mgmt/tm/sys/hardware/platform/0']['nestedStats']['entries']['marketingName']['description']
        globalSettings = bip.get('https://%s/mgmt/tm/sys/global-settings/' % (bigip)).json()
        bigipData['hostname'] = globalSettings['hostname']
        provision = bip.get('https://%s/mgmt/tm/sys/provision/' % (bigip)).json()
        provisionedModules = list()
        for module in provision['items']:
            if module.get('level'):
                if module['level'] != 'none':
                    provisionedModules.append(module['name'])
        bigipData['provisionedModules'] = json.dumps(provisionedModules)
    return bigipData

def check_for_bigip(ipaddress):
    hostCheck = requests.session()
    #adapter = requests.adapters.HTTPAdapter(max_retries=0)
    #hostCheck.mount('https://', adapter)
    hostCheck.verify = False
    try:
        bigiplogin = hostCheck.get('https://%s/tmui/login.jsp' % (ipaddress), timeout=2)
        if bigiplogin.status_code == 404:
            print ('BIG-IP Auth Page Not Found')
            return False
        elif '<title>BIG-IP' in bigiplogin.text:
            print ('BIG-IP Found')
            titleTag = re.search('<title>.*</title>', bigiplogin.text)
            possibleHostname = titleTag.group(0).split()[2]
            return possibleHostname
        else:
            print ('Unknown Problem')
            return False
    except requests.exceptions.RequestException as error:
        print ('Connection Error for %s' % (address))
        return False

if args.password:
    password = args.password
elif args.passfile:
    with open(args.passfile, 'r') as file:
        password = file.read().strip()
else:
   password = getpass.getpass('Enter Password for: %s: ' % (args.user))

if args.outputfile:
    workbook = xlsxwriter.Workbook(args.outputfile)
    bold = workbook.add_format({'bold': True})
    systemsSheet = workbook.add_worksheet('Systems')
    systemsSheet.write(0, 0, 'Hostname', bold)
    systemsSheet.write(0, 1, 'IP', bold)
    systemsSheet.write(0, 2, 'Model', bold)
    systemsSheet.write(0, 3, 'Serial Number', bold)
    systemsSheet.write(0, 4, 'Software Version', bold)
    systemsSheet.write(0, 5, 'Provisioned Modules', bold)
    row = 1

for network in args.networks:
    print ('Network: %s' % (network))
    for address in ip_network(network).hosts():
        print ('Address: %s' % (address))
        checkedIp = check_for_bigip(address)
        if checkedIp:
            print ('Found BIG-IP at: %s with hostname: %s' % (address, checkedIp))
            foundBigip = get_bigip_info(address, args.user, password)
            if args.outputfile:
                systemsSheet.write(row, 0, checkedIp)
                systemsSheet.write(row, 1, str(address))
                systemsSheet.write(row, 2, foundBigip['marketingName'])
                systemsSheet.write(row, 3, foundBigip['serialNumber'])
                systemsSheet.write(row, 4, foundBigip['version'])
                systemsSheet.write(row, 5, foundBigip['provisionedModules'])
                row += 1
            else:
                print ('BIG-IP Info: %s' % (json.dumps(foundBigip, indent=2)))

if args.outputfile:
    workbook.close()
