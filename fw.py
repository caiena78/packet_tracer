import json
import re
import socket
import threading
from netmiko import ConnectHandler
import os
import xmltodict





class fw:
    
    _devicelogin=dict
    _devicelist=[]
    firewalls=[]        
    ingressIF="insideIF"
    protocol="tcp"
    source_ip="10.10.10.10"
    source_port="1025"
    dest_ip="8.8.8.8"
    dest_port="443"
    trace=[]
    __devicefile="devices/devices.json"
    lock=threading.Lock()

    def __init__(self,devicefile="devices/devices.json") -> None:
        self.__devicefile=devicefile
        self.build_Device_list()
        
    def build_Device_list(self)->None:        
        if not os.path.exists(self.__devicefile):
            raise ValueError(f"file not foud: {self.__devicefile}")        
        with open(self.__devicefile) as r:
            data=r.read()
            data=json.loads(data)
            with self.lock:
                self._devicelist=data

    # 'cisco_ftd_ssh'
    # 'cisco_asa'
    def getDevice(self, ip,user,password,enable="",type='cisco_ios') -> dict:    
        device={
            'device_type': type,
            'host':   ip,
            'username': user,
            'password': password,
            'port' : 22,          # optional, defaults to 22   
            'conn_timeout' : 40,
            'global_delay_factor': 30,
            'secret':enable,          
        }      
        return device
    
    def sendCMD(self, device,command,textfsm=False):
        with  ConnectHandler(**device) as net_connect:                
            if net_connect.check_enable_mode() == False:
                net_connect.enable()
            Data = net_connect.send_command(command,use_textfsm=textfsm,read_timeout=45)        
        return Data
    
    def is_port_open(self, host,port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)  # Set a timeout for the connection attempt
        try:
            s.connect((host, port))
            s.close()
            return True
        except (socket.timeout, socket.error):
            return False
        
    def pattern_match(self,pattern,data):
        match=re.findall(pattern,data)
        if match:
            return match
        return None

    def __haCheck(self,logins:list):
        fwall1=self.is_port_open(logins[0]["host"],22)
        fwall2=self.is_port_open(logins[1]["host"],22)
        if fwall1==False and fwall2 == False:
            # we don't have any active firewall's in this set
            return None
        cmd="show failover"
        #print(f"Checking:{logins[0]['host']}")
        fo1=self.sendCMD(logins[0],cmd)
        #print(f"Checking:{logins[1]['host']}")
        fo2=self.sendCMD(logins[1],cmd)
        pattern=r"This host: .+ - Active"
        if self.pattern_match(pattern,fo1):
            #print(f"{logins[0]['host']} is active")
            return logins[0]
        if self.pattern_match(pattern,fo2):
            #print(f"{logins[1]['host']} is active")
            return logins[1]
        #print("None are active")
        return None

        
   
    def __packet_tracert_protocol(self):
        while self._devicelist:
            try:
                with self.lock:
                    fwall=self._devicelist.pop(0)    
                print(f"Connecting to:{fwall['ip']}")    
                username=os.environ.get(fwall["user"])   
                password=os.environ.get(fwall['password'])           
                enable=os.environ.get(fwall["enable"])
                interface=fwall[self.ingressIF]  
                cmd=f"packet-tracer input {interface} {self.protocol} {self.source_ip} {self.source_port} {self.dest_ip} {self.dest_port} xml"
                #modify this code               
                if type(fwall["ip"]) is str:
                    login=self.getDevice(fwall["ip"],username,password,enable,fwall["deviceType"])
                if type(fwall["ip"]) is list:
                    # print("Processing Mulit")
                    login1=self.getDevice(fwall["ip"][0],username,password,enable,fwall["deviceType"])
                    login2=self.getDevice(fwall["ip"][1],username,password,enable,fwall["deviceType"])
                    login=self.__haCheck((login1,login2))
                    if login==None:
                        print(f"Skipping:{login1["host"]} and {login2["host"]}")
                        continue
                    else:
                        print(f"connecting to active FW ({login['host']})")
                    
                traceData=self.sendCMD(login,cmd)            
                #add xml tag's to the xml i get from the ftd so i can parse it with xmltodict                
                j_trace=xmltodict.parse("<TRACE>"+traceData+"</TRACE>")
                with self.lock:
                    self.trace.append({
                        "cmd":cmd,
                        "name":fwall["name"],
                        "DeviceIP":login["host"],
                        "location":fwall["location"],
                        "Phase":j_trace["TRACE"]["Phase"],
                        "result":j_trace["TRACE"]["result"]
                    })
            except IndexError:
                break


    def packet_tracert_protocol(self,protocol="tcp",source_ip="10.10.10.10",dest_ip="8.8.8.8",dest_port="443",ingressIF="inside",source_port="1025",threadsCnt:int=20):
        self.build_Device_list()
        self.ingressIF=ingressIF
        self.protocol=protocol
        self.source_ip=source_ip
        self.source_port=source_port
        self.dest_ip= dest_ip
        self.dest_port=dest_port
        threads=[]
        for i in range(1,threadsCnt+1):        
            threads.append(threading.Thread(target=self.__packet_tracert_protocol))
            threads[i-1].start()    
        for t in threads:
            t.join()
        return self.trace



    def analysis(self):
            akey="ALLOW"
            dkey="DROP"
            result_output={akey:[],
                    dkey:[]
                    }    
            if len(self.trace)==0:
                return None
            for result in self.trace:
                if result["result"]["action"]=="allow":
                    result_output[akey].append({                        
                        "name":result['name'],
                        "phase":result['Phase'],
                        "result":result['result']
                    })
                    continue
                if result["result"]["action"]=="drop":
                    result_output[dkey].append({
                        "name":result['name'],
                        "phase":result['Phase'],
                        "result":result['result']
                    })
            return result_output
    

    def __packet_tracert_icmp(self):
        while self._devicelist:
            try:
                with self.lock:
                    fwall=self._devicelist.pop(0)    
                print(f"Connecting to:{fwall['ip']}")    
                username=os.environ.get(fwall["user"])   
                password=os.environ.get(fwall['password'])           
                enable=os.environ.get(fwall["enable"])
                interface=fwall[self.ingressIF]  
                cmd=f"packet-tracer input {interface} icmp {self.source_ip} {self.icmpType} {self.icmpCode} {self.destination_ip} xml "   
                print(fwall["deviceType"])   
                print(cmd)          
                if type(fwall["ip"]) is str:
                    login=self.getDevice(fwall["ip"],username,password,enable,fwall["deviceType"])
                if type(fwall["ip"]) is list:
                    login1=self.getDevice(fwall["ip"][0],username,password,enable,fwall["deviceType"])
                    login2=self.getDevice(fwall["ip"][1],username,password,enable,fwall["deviceType"])
                    login=self.__haCheck((login1,login2))
                    if login==None:
                        print(f"Skipping:{login1["host"]} and {login2["host"]}")
                        continue
                    else:
                        print(f"connecting to active FW ({login['host']})")
                traceData=self.sendCMD(login,cmd)            
                #add xml tag's to the xml i get from the ftd so i can parse it with xmltodict                
                j_trace=xmltodict.parse("<TRACE>"+traceData+"</TRACE>")
                with self.lock:
                    self.trace.append({
                        "cmd":cmd,
                        "name":fwall["name"],
                        "DeviceIP":login["host"],
                        "location":fwall["location"],
                        "Phase":j_trace["TRACE"]["Phase"],
                        "result":j_trace["TRACE"]["result"]
                    })
            except IndexError:
                break



    def packet_tracert_icmp(self,source_ip,destination_ip,ingressIF="inside",icmpType="8",icmpCode="0",threadsCnt:int=20):
        self.build_Device_list()
        self.ingressIF=ingressIF.lower()
        self.protocol="icmp"
        self.source_ip=source_ip
        self.destination_ip=destination_ip
        self.icmpType=icmpType
        self.icmpCode=icmpCode     
        threads=[]
        for i in range(1,threadsCnt+1):        
            threads.append(threading.Thread(target=self.__packet_tracert_icmp))
            threads[i-1].start()    
        for t in threads:
            t.join()
        return self.trace
        






# firewall=fw()
# #results=firewall.packet_tracert_protocol("tcp","8.8.8.8","10.10.10.10","443","outsideIF")
# results=firewall.packet_tracert_protocol("tcp","10.10.10.10","199.60.103.33","443","insideIF")
# results=firewall.packet_tracert_icmp("10.10.10.10","9.9.9.9")
# with open("all.json","w") as w:
#     w.write(json.dumps(results,indent=4 ))

# analysis=firewall.analysis()
# with open("analysis.json","w") as w:
#     w.write(json.dumps(analysis,indent=4))
