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
INTERFACE = 'en0' #default mac interface
DURATION = 300 #five minutes in seconds
COMMON_PORTS = [20, 21, 22, 23, 25, 53, 80, 443, 110, 135, 139, 445, 1433, 1434, 3306, 3389, 5900, 8080] #ports that are in common use and are often used in cyber attacks
#there are more ports but they are dpeending on port usgae and industry
MODEL_PATH = '/Users/apikorus/model/mymodel.pkl' #relevant model path that will be initially trained and used to analyze network
JSON_DATA_PATH = '/Users/apikorus/model/network_data.json' #relavant data of test in json format for easy to digest (in regards to ml model training)
CSV_DATA_PATH = '/Users/apikorus/model/network_data.csv'
#relevant data converted from json to csv for easy viewing for relevant stakeholder parties
NMAP_RESULTS_PATH = '/Users/apikorus/model/nmap_scan_results.txt'
#text descrition based results of nmap scan with all training considered and applied
LOGGING_PATH = '/Users/apikorus/model/network_activity.log'
#for more technical teams and bodies with in depth logging with explenations of how to debug 
# Set up logging

logging.basicConfig(filename=LOGGING_PATH, level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    # Load the pre-trained anomaly detection model
try:
    model = joblib.load(MODEL_PATH)
    logging.info("Loaded anomaly detection model successfully.")
except Exception as e:
    logging.error("Failed to load anomaly detection model: ", exc_info=True)
    sys.exit(1)
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
    
    def run_nmap(network_range):
        nmap_command = f"sudo nmap -sV -O -p{COMMON_PORTS} {network_range} --script=vuln -oN {NMAP_RESULTS_PATH}"
        try:
            result = subprocess.run(nmap_command, shell=True, stdout=subprocess.PIPE, universal_newlines=True)
            logging.info("Nmap scan completed. Check the results in nmap_scan_results.txt")
        except subprocess.CalledProcessError as e:
            logging.error("Failed to execute Nmap:", e)
        except Exception as e:
            logging.error(f"An unexpected error occurred while running Nmap: {e}")

    def load_pipeline(self, model_path):
        # Load the pre-trained model
        try:
            model = joblib.load(model_path)
            logging.info("Loaded anomaly detection model successfully.")
            # Create a pipeline with preprocessing steps and the loaded model
            pipeline = Pipeline([
                ('scaler', StandardScaler()),  # Example preprocessing step
                ('model', model)
            ])
            return pipeline
        except Exception as e:
            logging.error("Failed to load the model: ", exc_info=True)
            sys.exit(1)


# Utility functions for basic data collection using python
def ip_to_int(ip):
    try:
        parts = map(int, ip.split('.'))
        return sum(part << (8 * index) for index, part in enumerate(reversed(list(parts))))
    except ValueError:
        logging.error(f"Invalid IP address format: {ip}")
        return None

def is_common_port(port):
    return port in COMMON_PORTS

def interact_with_open_port(ip, port):
    try:
        s = socket.socket(socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(b'Hello\r\n')
        banner = s.recv(1024)
        logging.info(f"Received banner from {ip}:{port}: {banner}")
        s.close()
    except Exception as e:
        logging.error(f"Error while interacting with {ip}:{port}: {e}")

def extract_features(packet):
    try:
        # feature extraction logic in order to identify important properties that can be used to categorize and flag specific network occurences
        return {}
    except AttributeError as e:
        logging.warning(f"Missing attributes in packet: {e}")
    return {}

def is_anomalous(features):
    try:
        if len(features) == model.n_features_in_:
            prediction = model.predict([list(features.values())])
            return bool(prediction[0] == -1)
    except ValueError as e:
        logging.error(f"Error in prediction: {e}")
    return False

def capture_and_analyze_traffic(interface, duration):
    data_for_ml = []
    try:
        capture = pyshark.LiveCapture(interface=interface, only_summaries=False)
        capture.sniff(timeout=duration)
        logging.info("Traffic capture complete.")

        for packet in capture:
            features = extract_features(packet)
            if features:
                anomaly_detected = is_anomalous(features)
                try:
                    if anomaly_detected:
                        logging.warning(f"Anomalous traffic detected: {features}")
                        data_for_ml.append({'features': features, 'anomaly': anomaly_detected})
                except KeyboardInterrupt:
                                logging.info("Packet capture interrupted by user. Exiting.")
    except Exception as e:
        logging.error("Error in capture_and_analyze_traffic: ", exc_info=True)
        return data_for_ml

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
    except subprocess.CalledProcessError:
        logging.error(f"Failed to get network info for interface {interface}", exc_info=True)
        return None

def send_alert_webhook(message):
    webhook_url = 'https://yourwebhook.url'
    requests.post(webhook_url, json={"alert": message})


# Utility functions
# [Functions like ip_to_int, is_common_port, interact_with_open_port remain the same]

# Advanced packet processing and feature extraction
# [extract_features function remains largely the same]

# Advanced anomaly detection using ML pipeline
# [is_anomalous function remains largely the same]

def main():
    try:
        ip = get_network_info(INTERFACE)
        analyzer = NetworkAnalyzer(INTERFACE, DURATION)
        if not ip:
            logging.error(f"Failed to get network info for interface {INTERFACE}")
            return

        packets = asyncio.run(analyzer.capture_packets)()
        analyzer.analyze_traffic(packets)
        json_data_path = analyzer.analyze_traffic(packets)
        convert_json_to_csv(json_data_path, CSV_DATA_PATH)

        network_range = '.'.join(ip.split('.')[:-1]) + '.0/24'
        analyzer.run_nmap(network_range)
    except Exception as e:
        logging.error("An unexpected error occurred in main: ", exc_info=True)
        sys.exit(1)
if __name__ == "__main__":
    main()