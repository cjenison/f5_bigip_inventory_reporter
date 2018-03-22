#!/usr/local/bin/python3

# Home: https://github.com/cjenison/f5_bigip_inventory_reporter
# Author: Chad Jenison (c.jenison@f5.com)

import argparse
import sys
import requests
import getpass
import xlsxwriter
from ipaddress import ip_network

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='A tool to scan network looking for F5 BIG-IP Systems and then produce an XLSX Report File')
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--networks', '-n', help='Network(s) to scan (only IPv4 supported) in format networkaddr/masklength', required=True, nargs='*')
#parser.add_argument('--outputfile', '-o', help='Filename for XLSX output', required=True)
parser.add_argument('--outputfile', '-o', help='Filename for XLSX output')

args= parser.parse_args()

def get_auth_token(bigip, username, password):
    authbip = requests.session()
    authbip.verify = False
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % (bigip)
    authPost = authbip.post(authurl, headers=contentJsonHeader, auth=(username, password), data=json.dumps(payload)).json()
    if authPost.get('token'):
        token = authPost['token']['token']
        print ('Got Auth Token: %s' % (token))
    elif authPost.get('code') == 401:
        print ('Authentication failed due to invalid credentials; Exiting')
        quit()
    elif authPost.get('code') == 404:
        print ('attempt to obtain authentication token failed; will fall back to basic authentication; remote LDAP auth will require configuration of local user account')
        token = None
    return token

def get_bigip_info(bigip, username, password):
    bip = requests.session()
    bip.verify = False
    bigipData = {}
    token = get_auth_token(bigip, username, password)
    if token:
        bip.headers.update({'X-F5-Auth-Token': token})
    else:
        bip.auth = (username, password)
    version = bip.get('https://%s/mgmt/tm/sys/version/' % (bigip)).json()
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
            return True
        else:
            print ('Unknown Problem')
            return False
    except requests.exceptions.RequestException as error:
        print ('Connection Error for %s' % (address))
        return False

if args.outputfile:
    workbook = xlsxwriter.Workbook(args.outputfile)


for network in args.networks:
    print ('Network: %s' % (network))
    for address in ip_network(network).hosts():
        print ('Address: %s' % (address))
        if check_for_bigip(address):
            print ('Found BIG-IP at: %s' % (address))
