from flask import Flask, request, jsonify
import fw
from waitress import serve

app = Flask(__name__)


@app.route('/api/packet_tracert', methods=['POST'])
def packet_tracert():
    data = request.get_json()
    protocol = data.get('protocol')
    source_ip = data.get('source_ip')
    source_port = data.get('source_port')
    destination_ip = data.get('destination_ip')
    destination_port = data.get('destination_port')

    if not all([protocol, source_ip, source_port, destination_ip, destination_port]):
        return jsonify({"error": "Missing data"}), 400
   
    firewall=fw.fw()
    result = firewall.packet_tracert_protocol("tcp",source_ip,destination_ip,destination_port,"insideIF")    
    return jsonify({"result": result})


@app.route('/api/packet_tracert_icmp', methods=['POST'])
def packet_tracert_icmp():
    data = request.get_json()    
    source_ip = data.get('source_ip')    
    destination_ip = data.get('destination_ip')    

    if not all([source_ip, destination_ip]):
        return jsonify({"error": "Missing data"}), 400
   
    firewall=fw.fw()
    result = firewall.results=firewall.packet_tracert_icmp("10.10.10.10","9.9.9.9")   
    return jsonify({"result": result})


if __name__ == '__main__':
    #app.run(debug=False)
    serve(app, host="0.0.0.0", port=5000)