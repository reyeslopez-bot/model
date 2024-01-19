import pyshark
import json
import logging
import subprocess
import joblib
import socket
import pandas as pd
import sys
import requests
import asyncio
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn import datasets, metrics

# Constants and paths setup
INTERFACE = 'en0'  # Default mac interface
DURATION = 300  # Five minutes in seconds
COMMON_PORTS = [  # Ports in common use and often seen in cyberattacks
    20, 21, 22, 23, 25, 53, 80, 443, 110, 135, 139, 445, 1433, 1434, 3306, 3389, 5900, 8080
]
MODEL_PATH = '/Users/apikorus/model/mymodel.pkl'  # Path to the trained anomaly detection model
JSON_DATA_PATH = '/Users/apikorus/model/network_data.json'  # Path to save captured data in JSON format
CSV_DATA_PATH = '/Users/apikorus/model/network_data.csv'  # Path to save captured data in CSV format
NMAP_RESULTS_PATH = '/Users/apikorus/model/nmap_scan_results.txt'  # Path to save Nmap scan results
LOGGING_PATH = '/Users/apikorus/model/network_activity.log'  # Path for logging activity

# Set up logging
logging.basicConfig(filename=LOGGING_PATH, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Load the pre-trained anomaly detection model
try:
    model = joblib.load(MODEL_PATH)
    logging.info("Loaded anomaly detection model successfully.")
except Exception as e:
    logging.error(f"Failed to load anomaly detection model: {e}", exc_info=True)
    sys.exit(1)

def extract_features(packet):
    # Access packet fields using Pyshark's methods (e.g., packet.ip.src, packet.tcp.port)
    features = {}  # Initialize a dictionary to store features

    # Extract relevant features based on your requirements
    features['src_ip'] = packet.ip.src  # Example: Extract source IP address
    features['dst_ip'] = packet.ip.dst  # Example: Extract destination IP address
    features['src_port'] = packet.tcp.srcport  # Example: Extract source port number
    features['dst_port'] = packet.tcp.dstport  # Example: Extract destination port number
    features['bytes'] = packet.length  # Example: Extract packet length
    features['proto'] = packet.highest_layer  # Example: Extract highest layer protocol
    features['frequency'] = 1  # Example: Extract frequency of the packet
    features['timestamp'] = packet.sniff_timestamp  # Example: Extract timestamp of the packet
    
    return features  # Return the extracted features

class NetworkAnalyzer:
    def __init__(self, interface, duration, model_path):
        self.interface = interface
        self.duration = duration
        self.pipeline = self.load_pipeline(model_path)

    async def capture_packets(self):
        capture = pyshark.LiveCapture(interface=self.interface, only_summaries=False)
        await asyncio.wait_for(capture.sniff_continuously(packet_count=50), timeout=self.duration)
        return [packet for packet in capture]

    def process_packet(self, packet):
        features = extract_features(packet)
        return features

    def analyze_traffic(self, packets):
        data_for_ml = []
        for packet in packets:
            features = self.process_packet(packet)
            if features:
                anomaly_detected = is_anomalous(features)
                if anomaly_detected:
                    logging.warning(f"Anomalous traffic detected: {features}")
                data_for_ml.append({'features': features, 'anomaly': anomaly_detected})
        return data_for_ml

    def run_nmap(self, network_range):
        nmap_command = f"sudo nmap -sV -O -p{','.join(map(str, COMMON_PORTS))} {network_range} --script=vuln -oN {NMAP_RESULTS_PATH}"
        try:
            subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
            logging.info("Nmap scan completed. Check the results in nmap_scan_results.txt")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to execute Nmap: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while running Nmap: {e}")

    def load_pipeline(self, model_path):
        try:
            model = joblib.load(model_path)
            logging.info("Loaded anomaly detection model successfully.")
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('model', model)
            ])
            return pipeline
        except Exception as e:
            logging.error(f"Failed to load the model: {e}", exc_info=True)
            sys.exit(1)

def is_anomalous(features):
    try:
        prediction = model.predict([list(features.values())])
        return prediction[0] == -1
    except ValueError as e:
        logging.error(f"Error in prediction: {e}")
    return False

def convert_json_to_csv(json_data_path, csv_data_path):
    try:
        with open(json_data_path, 'r') as file:
            data = json.load(file)
        df = pd.json_normalize(data)
        df.to_csv(csv_data_path, index=False)
        logging.info(f"Data saved as CSV to {csv_data_path}")
    except Exception as e:
        logging.error(f"Failed to convert JSON to CSV: {e}")

def get_network_info(interface):
    try:
        ip_info = subprocess.check_output(['ifconfig', interface], text=True).strip()
        return ip_info
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to get network info for interface {interface}: {e}", exc_info=True)
        return None

def main():
    try:
        ip = get_network_info(INTERFACE)
        if not ip:
            logging.error(f"Failed to get network info for interface {INTERFACE}")
            return

        analyzer = NetworkAnalyzer(INTERFACE, DURATION, MODEL_PATH)
        packets = asyncio.run(analyzer.capture_packets())
        analyzed_data = analyzer.analyze_traffic(packets)

        with open(JSON_DATA_PATH, 'w') as f:
            json.dump(analyzed_data, f)
        logging.info("Packet analysis completed and saved to JSON.")

        convert_json_to_csv(JSON_DATA_PATH, CSV_DATA_PATH)

        network_range = '.'.join(ip.split('.')[:-1]) + '.0/24'
        analyzer.run_nmap(network_range)
    except Exception as e:
        logging.error(f"An unexpected error occurred in main: {e}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()