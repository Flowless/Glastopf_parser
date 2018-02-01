#!/usr/bin/python

import sys
import re
from collections import Counter

# Set file which should be used for all functions
if sys.argv[1:]:
	logfile = sys.argv[1]
else:
	logfile = raw_input("Please enter a log file to parse, e.g /var/log/secure: ")

# Returns the Counter object containing source IP addresses
def countTopIP():	
	file = open(logfile, 'r')
	ips = []
	
	for text in file.readlines():
		text = text.rstrip()
		regex = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',text)
		if regex:
			ips.extend(regex)
	
	# Converts to list
	occur = list(Counter(ips).items())	
	file.close()

	# Sort list by second element of tuples
	occur.sort(key=lambda tup: tup[1], reverse=True)		

	# Returns list object
	return occur

# Returns the Counter object containing HTTP methods
def countHTTPMethod():
	file = open(logfile, 'r')
	tmp = []
	for method in file.readlines():
		method = method.rstrip()
		regex = re.findall(r'(GET|POST|OPTIONS|DELETE|CONNECT|PUT|HEAD|TRACE|PATCH)', method)
		if regex:
			tmp.extend(regex)
	occur = list(Counter(tmp).items())

	# Count total rows, all methods together
	tot = sum((count for _, count in occur)) 

	# Create new and add the percentage to the tuple
	occur = [(m, c, c/tot) for m, c in occur]
	
	# Sort list by second element of tuples
	occur.sort(key=lambda tup: tup[1], reverse=True)		
	
	file.close()
	return occur

# Returns the Counter object containing all the URI's
def countTopURI():
	file = open(logfile, 'r')
	tmp = []
	for uri in file.readlines():
		url = uri.split(" ")
		try:
			if "/" not in url[6]:
				continue
			else:
				tmp.append(url[6])
		except IndexError as err:
			# Silenced debug messages here
			#print(err.args)
			continue

	occur = list(Counter(tmp).items())
	file.close()

	# Sort list by second element of tuples
	occur.sort(key=lambda tup: tup[1], reverse=True)			

	return occur

def main():
	
	# Get all unique IP's, along with occurrence
	print("-----------------------------------------------------")
	top_ips = countTopIP()
	#print(top_ips)

	# Print the first 10 elements in sorted list
	print("Top 10 Attacker IP's")
	for i in range(0,10):
		print(i+1, ": ", top_ips[i][0])	
	
	# Get all occurring methods, together with values
	print("-----------------------------------------------------")
	top_methods = countHTTPMethod()
	#print(top_methods)
	
	# Print sorted method list
	print("Top HTTP Methods")
	for i in range(0, len(top_methods)):
		print(i+1, ": ", top_methods[i][0], "-", top_methods[i][1])

	# Get all unique occurring URI's	
	print("-----------------------------------------------------")
	top_uris = countTopURI()
	#print(top_uris)
	print("Top URI's requested")
	for i in range(0,10):
		print(i+1, ": ", top_uris[i][0], "-", top_uris[i][1])

if __name__ == "__main__":
	main()
