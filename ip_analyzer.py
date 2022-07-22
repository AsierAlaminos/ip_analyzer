#LIBRARIES
import nmap
import requests
import sys
import re


print("  ___ ____       _    _   _    _    _  __   ____________ ____  ")
print(" |_ _|  _ \     / \  | \ | |  / \  | | \ \ / /__  / ____|  _ \ ")
print("  | || |_) |   / _ \ |  \| | / _ \ | |  \ V /  / /|  _| | |_) |")
print("  | ||  __/   / ___ \| |\  |/ ___ \| |___| |  / /_| |___|  _ < ")
print(" |___|_|     /_/   \_\_| \_/_/   \_\_____|_| /____|_____|_| \_\ \n\n")
                                                               

class IPanalyzer:
    def __init__(self, host):
        if host == 'localhost':
            host = '127.0.0.1'
        self.host = str(host)
        """
        self.ports_range = str(ports_range)
        self.type_scan = str(type_scan)
        """
    
    #THIS FUNCTION ACTS LIKE A PORT SCANNER LIKE NMAP
    def ports_scanner(self):
        global port_info, host_info, allports
        scn = nmap.PortScanner()
        scan = scn.scan(self.host, arguments = '-sCV --open --min-rate 5000')
        host_state = scn[self.host].state()
        allports = ""
        port_info = ""
        host_name = scn[self.host].hostname()
        if host_name == '':
            host_name = 'Unknown'
        for proto in scn[self.host].all_protocols():
            protocol = proto
        portcount = 0
        lport = scn[self.host][protocol].keys()
        for port in lport:
            if portcount == 0:
                allports = allports + str(port)
                portcount = 1
            else:
                allports = allports + ',' + str(port)
            port_state = str(scn[self.host][protocol][port]['state'])
            port_name = str(scn[self.host][protocol][port]['name'])
            port_service = str(scn[self.host][protocol][port]['product'])
            if port_name == '':
                port_name = 'Unknown'
            if port_service == '':
                port_service = 'Unknown'
            port_info = port_info + '|{:<12}|{:<12}|{:<14}|{:<31}|'.format(port, port_state, port_name, port_service) + '\n' + '#------------#------------#--------------#-------------------------------#' + '\n'
        host_info = str(self.host) + '  ' + '  State: ' + str(host_state) + '  ' + '  Name: ' + str(host_name)

    #THIS FUNCTION WORK LIKE A IP GEOLOCATOR WITH THE API OF https://whatismyipaddress.com/
    def geolocator(self):
        global response
        key = '' #put your api key here!
        ipaddress_lokkup = url + 'ip-address-lookup.php' + key + '&input=' + str(self.host)
        r = requests.get(ipaddress_lokkup)
        response = r.text

    #THIS FUNCTION SHOW THE SCAN TYPE YOU HAVE CHOOSE
    def show(self):
        if type_scan == 'port_scan':
            self.ports_scanner()
            host_info_long = 72
            print('##########################################################################')
            print('|{:^{}}|'.format(host_info, host_info_long))
            print('#------------#------------#--------------#-------------------------------#')
            print('|Puerto      |Estado      |Nombre        |Servicio                       |')
            print('#------------#------------#--------------#-------------------------------#')
            print(port_info)
            print(f'Puertos abiertos: {allports}')
        elif type_scan == 'geolocation':
            self.geolocator()
            print(response)
        else:
            print('Sintax: python ip_analyzer.py <ip> <scan_type>\n\nTipos de escaneo:\n\t-port_scan\n\t-geolocation')


#START THE SCRIPT
if __name__ == '__main__':
    try:
        if len(sys.argv) == 3:
            type_scan = str(sys.argv[2])
            host_ip = str(sys.argv[1])
            print('\n[*] Analizando\n')
            url = 'https://api.whatismyip.com/'
            analyzer = IPanalyzer(host_ip)
            analyzer.show()
        else:
            print('Sintax: python ip_analyzer.py <ip> <scan_type>\n\nTipos de escaneo:\n\t-port_scan\n\t-geolocation')
        
    except KeyboardInterrupt:
        print('\nSCAN FINISHED!!')
