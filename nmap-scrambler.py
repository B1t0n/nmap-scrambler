# -*- coding: utf-8 -*-
# !/usr/bin/python
#
# Auhtor: B1t0n
# Date  : 16.12.2018
# ------------------------


import argparse
import sys
import re
import os
import random


def parse_args():
    '''Parse Arguments'''

    parser = argparse.ArgumentParser(description='Scramble Nmap command IP and ports into multiple nmap command sin prepartinon to use with DNmap',
                                     epilog='Example: python ' + sys.argv[0] + ' -i <FILE CONTAINNING NMAP COMMAND> -o NMAP_COMMANDS.lst -n <NUMBER OF IPs per command> -p <NUMBER of ports per command>')

    parser.add_argument('-i', '--input', help='FILE CONTAINNING ONE NMAP COMMAND with all flags,IPs and ports to be scanned (TCP scan only)', required=True)
    parser.add_argument('-o', '--output', help='Output filename where the list of scrambled nmap commands will be wrritten', required=True)
    parser.add_argument('-n', '--ipcount', help='Number of IP addresses per generated nmap command', required=True)
    parser.add_argument('-p', '--portcount', help='Number of ports per generated nmap command', required=True)
    args = parser.parse_args()
    return args

args = parse_args()

#Input Params
infilename = args.input
outfilename = args.output
number_of_ips_per_command = int(args.ipcount)
number_of_ports_per_command = int(args.portcount)


#File & Arrays init
inputfile = open(infilename, 'r')
outputfile = open(outfilename, 'a')
ip_list = []
gen_cmd = []
nmap_cmd = inputfile.readline()
inputfile.close()

#Main nmap command disassemble
nmap_cmd = nmap_cmd.strip().split(" ")
for e,i in enumerate(nmap_cmd):
	#Case IP target
	if re.search("([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", i) is not None:
		#Case Just one ip
		if re.search("(^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$)", i) is not None:
			ip_list.append(i)
		#Case CIDR
		elif re.search("(^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9][0-9]?$)", i) is not None:
			ip_list.append(i)
		#Case e.g. 10.0.0.1-155 (IP range)
		elif re.search("(^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\-[0-9][0-9]?[0-9]?$)", i) is not None:
			ip_list.append(i)

	else: gen_cmd.append(i)


#Single IP list generation (Using built-in Nmap)
def gen_ip_list(ip_list):
	new_list = []
	spaced_ip_targets = " ".join(ip_list)
	nmap_out = os.popen("nmap -n -sn -Pn " + spaced_ip_targets).read()
	nmap_out_lines = nmap_out.split("\n")
	for line in nmap_out_lines:
		if "Nmap scan report for" in line:
			new_list.append(line.split(" ")[-1])
	return new_list

#Single port list generation (Using built-in Nmap)
def gen_ports_list(gen_cmd):
	for word in gen_cmd:
		if "-p-" in word:
			ports_list = range(1,65536)
			return ports_list
	ports_list = []
	nmap_cmd = " ".join(gen_cmd)
	nmap_cmd = nmap_cmd + " 127.0.0.1 -vvvv -oG -"
	nmap_out = os.popen(nmap_cmd).read()
#	print nmap_out
	nmap_out = nmap_out.split(";")[1]
	nmap_out = nmap_out.split(")")[0]
	nmap_out = nmap_out.split(",")
	ports_range_as_integers = []
	for i in nmap_out:
		if "-" in i: 
			ports_range_as_integers.extend(range(int(i.split("-")[0]),int(i.split("-")[1])+1))
			for int_port in ports_range_as_integers:
				ports_list.append(str(int_port))
			ports_range_as_integers = []
		else: ports_list.append(i)
	return ports_list

#Base nmap command assemble (Without ports or ips)
def get_base_nmap_cmd(gen_cmd):
	base_cmd = []
	for i in gen_cmd:
		if "-p" in i: continue
		elif "--top-ports" in i:continue
		elif "," in i:continue
		elif re.search("(^[0-9]+$)", i) is not None:continue
		elif re.search("(^[0-9]+\-[0-9]+$)", i) is not None:continue
		else: base_cmd.append(i)
	base_cmd = " ".join(base_cmd)
	return base_cmd

#print ip_list
#print gen_cmd
raw_ip_list = gen_ip_list(ip_list)
ports_list = gen_ports_list(gen_cmd)
base_nmap_cmd = get_base_nmap_cmd(gen_cmd)


#print raw_ip_list
#print ports_list
#print base_nmap_cmd

print "Preparing Nmap commands..."
print "Number of probes:", len(raw_ip_list)*len(ports_list)

#Scramble
print "Scrambling IP addresses..."
random.shuffle(raw_ip_list)
print "Scrambling Ports..."
random.shuffle(ports_list)
#Grouping IPs
grouped_ips_list = [raw_ip_list[n:n+number_of_ips_per_command] for n in range(0, len(raw_ip_list), number_of_ips_per_command)]
#Grouping ports
grouped_ports_list = [ports_list[n:n+number_of_ports_per_command] for n in range(0, len(ports_list), number_of_ports_per_command)]


print "Estimated number of commands:", len(grouped_ips_list)*len(grouped_ports_list)
#Consider the number of cmds since it takes time for dnmap to load it (Around half hour for 1 million cmds (EC2 t2.micro instance)
#Also, consider the number of cmds as the number of .nmap files that are gonna be created, zipped, transferred and parsed.


#print grouped_ports_list
#print grouped_ips_list
nmap_cmds = []
for group_of_ports in grouped_ports_list:
	for gorup_of_ips in grouped_ips_list:
		#Need to find a better refernce for the outputname
		single_cmd = base_nmap_cmd + " -p" + str(",".join(group_of_ports)) + " " + " ".join(gorup_of_ips) + " -oA " + gorup_of_ips[0] + "_" + gorup_of_ips[-1] + ".Port" + str("_".join(group_of_ports))
		nmap_cmds.append(single_cmd)


print "Scrambling Commands..."
random.shuffle(nmap_cmds)

print "Writing to file..."
for cmd in nmap_cmds:
	outputfile.write(cmd + "\n")
outputfile.close()


#print ports_list
print "Number of ports to scan:", len(ports_list)
print "Total IP addresses:", len(raw_ip_list)
print "Total cmds created:", len(nmap_cmds)
