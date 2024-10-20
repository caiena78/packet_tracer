from flask import Flask, json, request, jsonify
import fw
from waitress import serve

app = Flask(__name__)


@app.route('/api/packet_tracert', methods=['POST'])
def packet_tracert():
    data = request.get_json()
    try:
        if "ingressIF" in data:
            ingressIF=data.get('ingressIF')
            ingressIF=ingressIF.lower()
        else:
            ingressIF="inside"
        protocol = data.get('protocol')
        source_ip = data.get('source_ip')
        source_port = data.get('source_port')
        destination_ip = data.get('destination_ip')
        destination_port = data.get('destination_port')
        if not all([protocol, source_ip, source_port, destination_ip, destination_port]):
            return jsonify({"error": "Missing data"}), 400
    
        firewall=fw.fw()
        if not firewall.is_valid_interface(ingressIF):
            return jsonify(f"error:not valid interface ({ingressIF})")
        if not firewall.is_valid_ipv4(source_ip):
            return jsonify(f"error:not valid Source ip ({source_ip})")
        if not firewall.is_valid_ipv4(destination_ip):
            return jsonify(f"error:not valid destination ip ({destination_ip})")
        result = firewall.packet_tracert_protocol("tcp",source_ip,destination_ip,destination_port,ingressIF)    
    except Exception as e:
        print(e)
        return jsonify({"error": e}), 400
    return jsonify({"result": result})


@app.route('/api/packet_tracert_icmp', methods=['POST'])
def packet_tracert_icmp():
    print("ICMP")    
    data = request.get_json()    
    # testing 
    print(json.dumps(data,indent=4))
    try:
        source_ip = data.get('source_ip')    
        destination_ip = data.get('destination_ip')    
        if "ingressIF" in data:
            ingressIF=data.get('ingressIF')
            ingressIF=ingressIF.lower()
        else:
            ingressIF="inside"
        if "icmpType" in data:
            icmpType=data.get('icmpType')
        else:
            icmpType="8"
        if "icmpCode" in data:
            icmpCode=data.get('icmpCode')
        else:
            icmpCode="0"
        if not all([source_ip, destination_ip]):
            print("Missing data")
            return jsonify({"error": "Missing data"}), 400
        firewall=fw.fw()
        if not firewall.is_valid_interface(ingressIF):
            return jsonify(f"error:not valid interface ({ingressIF})")
        if not firewall.is_valid_ipv4(source_ip):
            return jsonify(f"error:not valid Source ip ({source_ip})")
        if not firewall.is_valid_ipv4(destination_ip):
            return jsonify(f"error:not valid destination ip ({destination_ip})")
        result = firewall.packet_tracert_icmp(source_ip,destination_ip,ingressIF,icmpType,icmpCode)   
    except Exception as e:
        print(e)
        return jsonify({"error": e}), 400
    return jsonify({"result": result})


if __name__ == '__main__':
    #app.run(debug=False)
    ipaddress="0.0.0.0"
    port=5000
    print(f"Server running, ip:{ipaddress}:{port}")
    serve(app, host=ipaddress, port=port)