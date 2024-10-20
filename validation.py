import ipaddress
from marshmallow import Schema, fields, ValidationError


def is_valid_ipv4(address):
    try:
        # Try to create an IPv4 address object
        ip = ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False

def interface_validation(value):
    interfaces="inside|outside"
    if not isinstance(value,str):
        raise ValidationError("ingressIF must be a string")
    if value not in interfaces:
        raise ValidationError("ingressIF must be (inside or outside)")
    

def ICMP_validation(value):
    if not isinstance(value,str):
        raise ValidationError("Protocol must be a string")
    if value != "icmp":
        raise ValidationError("Protocol is not set to ICMP")

def IP_validation(value):
    if not isinstance(value,str):
        raise ValidationError("IP must be a string") 
    if not is_valid_ipv4(value):
        raise ValidationError("IP address is invalid") 

def icmpType_validation(value):    
    errormsg="icmpType must be a number in this Range (0-255)"
    if not isinstance(value,str):
        raise ValidationError("icmpType must be a string") 
    try:
        intValue=int(value)
        if 0 <= intValue <= 255:
            return
        else:
            raise ValidationError(errormsg)
    except:    
        raise ValidationError(errormsg)
     
def icmpCode_validation(value):    
    errormsg="icmp code must be a number in this Range (0-255)"
    if not isinstance(value,str):
        raise ValidationError("icmp code must be a string") 
    try:
        intValue=int(value)
        if 0 <= intValue <= 255:
            return
        else:
            raise ValidationError(errormsg)
    except:    
        raise ValidationError(errormsg)


class icmpSchema(Schema):
    ingressIF= fields.Str(required=True,validate=interface_validation)
    protocol=fields.Str(required=True,validate=ICMP_validation) 
    source_ip=fields.Str(required=True,validate=IP_validation) 
    destination_ip=fields.Str(required=True,validate=IP_validation) 
    icmpType=fields.Str(required=True,validate=icmpType_validation)
    icmpCode=fields.Str(required=True,validate=icmpCode_validation)


def protocal_validation(value):
    protocollist="tcp|udp"
    if not isinstance(value,str):
        raise ValidationError("Protocol must be a string") 
    if value.lower() not in protocollist:
        raise ValidationError("Protocol must be (TCP/UPD)") 
    
def Port_validation(value):
    errormsg="TCP/UDP Ports must be between [1-65535]"
    if not isinstance(value,str):
        raise ValidationError("tcp Ports must be a string") 
    try:
        tcp_port=int(value)
        if 0 < tcp_port <= 65535:
            return
        else:
            raise ValidationError(errormsg)
    except:    
        raise ValidationError(errormsg)



class TcpUdpScheme(Schema):
    ingressIF= fields.Str(required=True,validate=interface_validation)
    protocol=fields.Str(required=True,validate=protocal_validation) 
    source_ip=fields.Str(required=True,validate=IP_validation) 
    destination_ip=fields.Str(required=True,validate=IP_validation) 
    source_port=fields.Str(required=True,validate=Port_validation)
    dest_port=fields.Str(required=True,validate=Port_validation)
    

# user_data={
#     "ingressIF":"inside",
#     "protocol":"icmp",
#     "source_ip":"10.10.10.10",
#     "destination_ip":"8.8.8.8",
#     "icmpType":"0",
#     "icmpCode":"0"
# }

# schema = icmpSchema()

# try:
#     result = schema.load(user_data)
#     print("Valid data:", result)
# except ValidationError as err:
#     print("Validation errors:", err.messages)


# user_data={
#     "ingressIF":"inside1",
#     "protocol":"tcp",
#     "source_ip":"10.10.10.10",
#     "destination_ip":"8.8.8.8",
#     "source_port":"1025",
#     "dest_port":"443"
# }

# schema=TcpUdpScheme()

# try:
#     result = schema.load(user_data)
#     print("Valid data:", result)
# except ValidationError as err:
#     print("Validation errors:", err.messages)
