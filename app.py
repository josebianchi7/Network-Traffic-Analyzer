# Description: Program to listen for GET requests and respond
#   with data from local log file.

import json
from flask import Flask, jsonify
from credentials import host_ip
from credentials import host_port


app = Flask(__name__)

log_file = 'traffic_log.txt'


@app.route('/traffic_report', methods=['GET'])
def get_log_data():
    """
    Returns log file content.
    """
    log_data = []
    try:
        # Open the log file and read the contents
        with open(log_file, 'r') as file:
            lines = file.readlines()
        
            # Filter the log data for the current date
            for line in lines:
                log_data.append(line)

    except Exception as e:
        print(f"Error reading log file: {e}")

    if log_data:
        return jsonify(log_data), 200
    else:
        return jsonify({"error": "No log data found for today."}), 404

if __name__ == "__main__":
    # Start the Flask web server
    app.run(host=host_ip, port=host_port)
