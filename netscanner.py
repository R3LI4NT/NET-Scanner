#!/usr/bin/env python

from scapy.all import ARP, Ether, srp
import os, sys
import socket
import pyfiglet
import time

#COLORS
RED = '\033[1;31m'
BLUE = '\033[1;34m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
MAGENTA = '\033[1;35m'
WHITE = '\033[1;37m'
CYAN = '\033[1;36m'
END = '\033[0m'

os.system("clear")

banner = pyfiglet.figlet_format("NET-Scanner")
print(banner)
copyright = ("Github: \033[1;37mR3LI4NT\033[0m")
print(copyright)


def menu():
	print("""
\033[1;37m[\033[1;31m1\033[1;37m] \033[0;32mCheck your internet connection\033[0m
\033[1;37m[\033[1;31m2\033[1;37m] \033[0;32mPublic address of Websites\033[0m
\033[1;37m[\033[1;31m3\033[1;37m] \033[0;32mPort scanner\033[0m
\033[1;37m[\033[1;31m4\033[1;37m] \033[0;32mScan IP's and MAC's on your Wi-Fi\033[0m
\033[1;37m[\033[1;31m0\033[1;37m] \033[0;32mExit\033[0m
""")

def restart():
    if input("\n\033[1;37mBack to main menu \033[0;32my\033[1;37m/\033[0;31mn\033[0;m\n\033[1;37m->\033[0m ").upper() != "Y":
        time.sleep(1)
        os.system("clear")
        print(banner)
        print(copyright)
        print("\n\033[1;32mGoodbye, Friend\033[0;m\033[1;37m!\033[0;m")
        tool = exit(0)
    os.system("python3 netscanner.py")    	

def check_network():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	print("Checking connection...\n")
	s.settimeout(2)
	try:
		s.connect(('nmap.org',443))
		print("\033[0;32m[Connected]\033[0m")

	except:
		print("\033[0;31m[Disconnected]")

def Public_IP():
    hostName = input("Target: ")
 
    ipaddress = socket.gethostbyname(hostName)
    print("IP Address:\033[0;32m {}\033[0m".format(ipaddress))

def ScanManual():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket.setdefaulttimeout(2)

    target = input("Target: ")
    port = int(input("Port: "))
    print("")

    def scan(port):
        if sock.connect_ex((target,port)):
            print("-" * 30,"\nPort",port,"is \033[0;31mclosed\033[0m")
            print("-" * 30)


        else:
        	print("-" * 30)
        	print("Port", port,"is \033[0;32mopen\033[0m")
        	print("-" * 30)

    scan(port) 


def ScanRandom():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    socket.setdefaulttimeout(1)

    target = input("Target: ")
    print("")

    def scanning(port):
        if sock.connect_ex((target,port)):
            print("-" * 30,"\nPort",port,"is \033[0;31mclosed\033[0m")
            print("-" * 30)

        else:
        	print("-" * 30)
        	print("Port", port,"is \033[0;32mopen\033[0m")
        	print("-" * 30)

    for port in range(1,65536):
        scanning(port)      


def NetworkScan():
	target = input("Enter the IP and range (ex \033[0;33m192.168.1.1/24\033[0m): ")
	print(" ")
	print("-" * 40)

	arp = ARP(pdst=target)

	etherMAC = Ether(dst="ff:ff:ff:ff:ff:ff")

	packet = etherMAC/arp

	r = srp(packet, timeout=3, verbose=0)[0]


	clients = []

	for sent, received in r:
		clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
	print(" IP" + " "*18+" MAC")
	print("-" * 40)
	for client in clients:
	    print("{:16}    {}".format(client['ip'], client['mac']))

def durationScan():
	start = time.time()
	end = time.time()
	print(f'Time taken: {end-start:.2f} seconds')

menu() 

option = int(input("\033[1;37m-> \033[0m"))

if option == 1:
	check_network()
	restart()


elif option == 2:
	Public_IP()
	restart()

elif option == 4:
	NetworkScan()
	durationScan()
	restart()

elif option == 0:
	exit(0)		


while option == 3:
	os.system("clear")
	print(banner)
	print(copyright)
	print("\n\033[1;37m[\033[1;31m1\033[1;37m]\033[0m \033[0;32mManual scan")
	print("\033[1;37m[\033[1;31m2\033[1;37m]\033[0m \033[0;32mRandom scan (\033[0;33m1\033[0;37m,\033[0;33m65536\033[0;32m)\033[0m")

	option = int(input("\n\033[1;37m-> \033[0m"))

	if option == 1:
		ScanManual()
		durationScan()
		restart()

	elif option == 2:
		ScanRandom()
		durationScan()
		restart()	

	
