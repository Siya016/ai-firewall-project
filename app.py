from flask import Flask, redirect, url_for, request, jsonify, send_from_directory
from flask_cors import CORS
from urllib.parse import urlparse, parse_qs

from pyflowmeter import sniffer

from prediction import FirewallModel
import re


TYPES_DICT = {
        'TCP SYN flood': 'test_files/pkt.TCP.synflood.spoofed.pcap',
        'UDP null': 'test_files/pkt.UDP.null.pcapng',
        'Real time traffic': 'Real time traffic',
        'TCP reflection': 'test_files/amp.TCP.reflection.SYNACK.pcap',
        'UDP.rdm.fixedlength': 'test_files/pkt.UDP.rdm.fixedlength.pcapng',
        'UDP LDAP': 'test_files/amp.UDP.memcached.ntp.cldap.pcap',
    }

# Define some basic malicious patterns for SQL Injection and XSS
SQL_INJECTION_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",  # SQL Injection basics
    r"(\%22)|(\")|(\%3D)|(\=)|(\%2F)|(/)",  # SQL metacharacters
    r"(union(\%20|\+)+select)",  # UNION SELECT pattern
    r"(select(\%20|\+)+(from|sleep|benchmark))",  # SELECT pattern
    r"(insert(\%20|\+)+into)",  # INSERT pattern
    r"(delete(\%20|\+)+from)",  # DELETE pattern
    r"(drop(\%20|\+)+(table|database))"  # DROP pattern
]

XSS_PATTERNS = [
    r"((\%3C)|<)[^\n]+((\%3E)|>)",  # Basic XSS <script> tags
    r"((\%22)|\")((\%2F)|/)",  # Closing quotes and tags
    r"((\%27)|\')((\%3E)|>)",  # Closing quote and bracket
    r"script(\%20|\+)*\((.*?)\)",  # JavaScript function call
]

model = FirewallModel()
traffic_sniffer = None
sniffer_created = False
app = Flask(__name__)
CORS(app)

predicted_data = []
url_data = []

# URL pattern to check if it is HTTP or HTTPS
HTTP_URL_PATTERN = re.compile(r'^http://')
HTTPS_URL_PATTERN = re.compile(r'^https://')

# Serve static files from the dist folder
@app.route('/assets/<path:filename>')
def static_files(filename):
    return send_from_directory('./client/dist/assets', filename)

# Handle 404 errors
@app.errorhandler(404)
def not_found(e):
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    return send_from_directory('./client/dist', 'index.html')

@app.route('/traffic-analysis')
def traffic_analysis():
    return send_from_directory('./client/dist', 'index.html')

@app.route('/url-analysis')
def url_analysis():
    return send_from_directory('./client/dist', 'index.html')

@app.route("/send_traffic", methods=["POST"])
def post_data():
    if request.is_json:
        data = request.get_json()
        confidences, predcted_classes = model.predict(data["flows"])
        for (flow, confidence, predcted_class) in zip(
            data["flows"], confidences, predcted_classes
        ):
            predicted_data.append(
                {
                    "type": predcted_class,
                    "src_ip": f'{flow["src_ip"]}:{flow["src_port"]}',
                    "dst_ip": f'{flow["dst_ip"]}:{flow["dst_port"]}',
                    "confidence": f"{confidence:.2%}",
                    "timestamp": flow["timestamp"],
                }
            )

        return jsonify({"message": "Data received successfully"}), 200
    else:
        return jsonify({"error": "Invalid JSON data in the request"}), 400


@app.route("/get_data", methods=["GET"])
def get_data():
    return jsonify(predicted_data)

@app.route('/start_sniffer', methods=['POST'])
def start_sniffer():
    if request.is_json:
        data = request.get_json()
        test_type = data['file']
        test_file = TYPES_DICT[test_type]
        reload_sniffer(test_file)
        return jsonify({"message": "Data received successfully"}), 200
    else:
        return jsonify({"error": "Invalid JSON data in the request"}), 400


# Function to detect SQL Injection
def detect_sql_injection(url):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param, value in query_params.items():
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, value[0], re.IGNORECASE):
                return True
    return False

# Function to detect XSS
def detect_xss(url):
    for pattern in XSS_PATTERNS:
        if re.search(pattern, url, re.IGNORECASE):
            return True
    return False
@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    ip_address = data.get('ip')

    if not url:
        return jsonify({"error": "URL not provided"}), 400

    # Analyze the URL
    if detect_sql_injection(url):
        # Log the URL and IP address
        url_data.append(
            {
                "url": url,
                "ip_address": ip_address,
                "status": "Blocked"
            }
        )
        return jsonify({"error": "Malicious SQL Injection detected!"}), 400
    elif detect_xss(url):
        url_data.append({
            "url": url,
            "ip_address": ip_address,
            "status": "Blocked"

        })
        return jsonify({"error": "Malicious XSS detected!"}), 400
    else:
        url_data.append({
            "url": url,
            "ip_address": ip_address,
            "status": "Allowed"

        })
        return jsonify({"message": "URL is safe"}), 200

# New /url_analysis endpoint
@app.route('/analyse-url', methods=['GET'])
def analyse_url():
    return jsonify(url_data)

def reload_sniffer(test_file):
    print(test_file)
    global traffic_sniffer
    global sniffer_created
    global predicted_data
    if sniffer_created:
        try:
            traffic_sniffer.stop()
            traffic_sniffer.join()
        except:
            pass
    else:
        sniffer_created = True

    predicted_data = []
    if test_file == 'Real time traffic':
        traffic_sniffer = sniffer.create_sniffer(
            input_interface=None,
            server_endpoint='http://127.0.0.1:5001/send_traffic',
        )
    else:
        traffic_sniffer = sniffer.create_sniffer(
            input_file=test_file,
            server_endpoint='http://127.0.0.1:5001/send_traffic',
        )
    traffic_sniffer.start()

if __name__ == '__main__':
    app.run(debug=True,  port=5001)
