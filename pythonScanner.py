#! /usr/bin/python
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys
import argparse
from datetime import datetime
from time import strftime

#get initial scan information form user
try:	
	target = raw_input("> Enter Target IP Address: ")
	print "\n> Which Protocol Would You Like To Use?"
	print ">T = TCP, U = UDP"
	protocol = raw_input("> Enter Protocol: ")
	if protocol != "T" and protocol != "U":
		print "I told you to enter one of the above letters, you loser."
		print "exiting now."
		sys.exit(1)
	min_port = raw_input("> Enter Minimum Port Number: ")
	max_port = raw_input("> Enter Maximum Port Number: ")
	try:
		if int(min_port) >= 0 and int(max_port) >= 0 and int(max_port) >= int(min_port):
			pass
		else:
			print "Invalid port range"
			print "you suck."
			sys.exit(1)
	except Exception:
		print "You put something in here that you shouldn't have."
		print "loser."
		sys.exit(1)
except KeyboardInterrupt:
	print "\n Shutdown requested. Good night!"
	sys.exit(1)

#create a range of ports to scan
ports = range(int(min_port), int(max_port) +1)
start_clock = datetime.now()
SYNACK = 0x12
RSTACK = 0x14

#make sure the target host is up
def checkhost(ip):
	conf.verb = 0
	try:
		ping = sr1(IP(dst = ip)/ICMP(), timeout = 1, verbose = 0)
		print "\nHost is alive, begining scan..."
	except Exception:
		print "\nHost is unresponsive"
		print "Ending script now..."
		sys.exit(1)

#scan the designated ports using TCP
def scanportTCP(port):
	srcport = RandShort()
	conf.verb = 0

	SYNACKpkt = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S"), timeout=1, verbose=0)
	if SYNACKpkt != None:	
		pktflags = SYNACKpkt.getlayer(TCP).flags	
		if pktflags == SYNACK:
			return True
			RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R")
			send(RSTpkt)
		else:
			return False
	else:
		return False

#Scan the designated ports using UDP
def scanportUDP(port):
	srcport = RandShort()
	conf.verb = 0

	SYNACKpkt = sr1(IP(dst = target)/UDP(dport = port), timeout=1, verbose=0)
	if SYNACKpkt == None:	
		return True

	else:
		return False

#check host before port scanning
checkhost(target)
print "Scanning started at " + strftime("%H:%M:%S") + "\n"

for port in ports:
	if protocol == "U":
		status = scanportUDP(port)
	else:
		status = scanportTCP(port)
	if status == True:
		print "Port " + str(port) + ": Open"

stop_clock = datetime.now()
total_time = stop_clock - start_clock
print "\nScan Finished!"
print "Total Scan Duration: " + str(total_time)
