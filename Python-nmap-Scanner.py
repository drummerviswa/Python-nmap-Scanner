#install pip and python in whatever operating system you are using.
#Install Python-nmap by pip install python-nmap
#Then Add that to your PATH
import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool")
print("""----------------------------------------------------------------------------
_____                                                  _                    
|  __ \                                               (_)                  
| |  | |_ __ _   _ _ __ ___  _ __ ___   ___ _ ____   ___ _____      ____ _ 
| |  | | '__| | | | '_ ` _ \| '_ ` _ \ / _ \ '__\ \ / / / __\ \ /\ / / _` |
| |__| | |  | |_| | | | | | | | | | | |  __/ |   \ V /| \__ \\ V  V / (_| |
|_____/|_|   \__,_|_| |_| |_|_| |_| |_|\___|_|    \_/ |_|___/ \_/\_/ \__,_|

""")
print("©Copyright by Drummerviswa")
print("Follow me on Instagram @drummerviswa")
print("<---------------------------------------------------------------------------->")

ip_addr = input("Please enter the IP address you want to scan:   \n")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan 
                4)OS Detection
                5)Fast Scan\n""")
                
if resp == '1':
    print("You have selected option 1 which is SYN ACK Scan")
elif resp == '2' :
    print("You have selected option 2 which is UDP Scan")
elif resp == '3' :
    print("You have selected option 3 which is Comprehensive Scan")
elif resp == '4' :
    print("You have selected option 4 which is OS Detection")
elif resp == '5' :
    print("You have selected option 5 which is Fast scan")

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: \n", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: \n", scanner[ip_addr]['tcp'].keys())
    
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status: \n", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: \n", scanner[ip_addr]['udp'].keys())

elif resp == '3':
    print("Nmap Version: \n", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status: \n", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: \n", scanner[ip_addr]['tcp'].keys())

elif resp == '4':
    scanner.scan(ip_addr, arguments='-O')
    print(scanner[ip_addr]['osmatch'][0]['osclass'][0]['osfamily'])

elif resp == '5' :
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-500', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: \n", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: \n", scanner[ip_addr]['tcp'].keys())
else: print("Please enter valid options")
