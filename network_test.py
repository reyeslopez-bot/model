import pyshark
import json
import logging
import subprocess
import joblib
import pandas as pd
import sys
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import os
import traceback
import numpy as np

# Constants and paths setup
INTERFACE = 'en0'  # Default mac interface
DURATION = 300  # Duration in seconds
MODEL_PATH = os.environ.get('MODEL_PATH', '/Users/apikorus/model/trained_model.pkl')  # Path to the anomaly detection model
JSON_DATA_PATH = os.environ.get('JSON_DATA_PATH', '/Users/apikorus/model/network_data.json')  # Path to save captured data in JSON
LOGGING_PATH = os.environ.get('LOGGING_PATH', '/Users/apikorus/model/network_activity.log')  # Path for logging activity
# Parse COMMON_PORTS from environment or use default
common_ports_env = os.environ.get('COMMON_PORTS')
COMMON_PORTS = json.loads(common_ports_env) if common_ports_env else [20, 21, 22, 23, 25, 53, 80, 443, 110, 135, 139, 445, 1433, 1434, 3306, 3389, 5900, 8080]
NMAP_RESULTS_PATH = os.environ.get('NMAP_RESULTS_PATH', '/Users/apikorus/model/nmap_scan_results.txt')  # Path to save Nmap scan results
CSV_DATA_PATH = os.environ.get('CSV_DATA_PATH', '/Users/apikorus/model/network_data.csv')  # Path to save captured data in CSV

# Setup logging
logging.basicConfig(filename=LOGGING_PATH, level=logging.DEBUG)

class NetworkAnalyzer:
    def __init__(self):
        self.interface = INTERFACE
        self.duration = DURATION
        # Correctly pass MODEL_PATH to the load_model method
        self.model = self.load_model(MODEL_PATH) 
        self.pipeline = self.create_pipeline(self.model)

    def load_model(self, model_path):
        if not os.path.exists(model_path):
            logging.error(f"Model file not found at {model_path}")
            sys.exit(1)
        model_size = os.path.getsize(model_path)
        logging.info(f"Model size: {model_size} bytes")
        try:
            return joblib.load(model_path)
        except Exception as e:
            logging.error(f"Failed to load model: {e}", exc_info=True)
            sys.exit(1)

    # ... rest of the NetworkAnalyzer class ...
    def create_pipeline(self, model):
        try:
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('model', model)
            ])
            logging.info("Pipeline created successfully.")
            return pipeline
        except Exception as e:
            logging.error(f"Failed to create pipeline: {e}", exc_info=True)
            sys.exit(1)
            
    def capture_packets(self):
        logging.info("Starting packet capture with tcpdump")

        # Define the path for the temporary file
        temp_file = "/tmp/captured_packets.pcap"
        
        tcpdump_command = f"sudo tcpdump -i {INTERFACE} -c 50 -w {temp_file} -q"

        try:
            # Run tcpdump and wait for it to complete
            subprocess.run(tcpdump_command, shell=True, timeout=self.duration)
            logging.info("Packet capture completed with tcpdump")
            
            os.system(f"sudo chown $(whoami) {temp_file}")
            # Change file permissions (if necessary)
            os.chmod(temp_file, 0o644)

            # Read the captured packets from the file
            capture = pyshark.FileCapture(temp_file, only_summaries=False)
            packets = [packet for packet in capture]
            logging.info(f"Total packets read from file: {len(packets)}")

        except subprocess.TimeoutExpired:
            logging.warning("Packet capture with tcpdump timed out")
        except Exception as e:
            logging.error(f"Error during packet capture with tcpdump: {e}")
            logging.debug(f"Stack Trace: {traceback.format_exc()}")
        finally:
            # Clean up: remove the temporary file
            if os.path.exists(temp_file):
                os.remove(temp_file)

        return packets   
    
    # Define a function to extract features from a packet
    @staticmethod
    def extract_features(packet):
        features = {}
        # Access packet fields using Pyshark's methods (e.g., packet.ip.src, packet.tcp.port)
        # Extract relevant features based on your requirements

        if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'srcport') and hasattr(packet.tcp, 'dstport'):
            features['src_port'] = packet.tcp.srcport
            features['dst_port'] = packet.tcp.dstport
            features['bytes'] = packet.length  # Example: Extract packet length
            features['proto'] = packet.highest_layer  # Example: Extract highest layer protocol
            features['frequency'] = 1  # Example: Extract frequency of the packet
            features['timestamp'] = packet.sniff_timestamp  # Example: Extract timestamp of the packet
            
        return features  # Return the extracted features
    
    def analyze_traffic(self, packets):
        data_for_ml = []
        for packet in packets:
            features = self.extract_features(packet)
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

    def load_pipeline(self):  # Correct method definition
        try:
            model = joblib.load(MODEL_PATH)
            pipeline = Pipeline([
                ('scaler', StandardScaler()),
                ('model', model)
            ])
            logging.info("Loaded anomaly detection model successfully.")
            return pipeline
        except Exception as e:
            logging.error(f"Failed to load the model: {e}", exc_info=True)
            sys.exit(1)

def is_anomalous(features):
    model = joblib.load(MODEL_PATH)
    if model is None:
        logging.error("Model is not loaded. Cannot perform anomaly detection.")
        return False

    try:
        # Ensuring features are in the correct format for prediction
        feature_values = np.array(list(features.values())).reshape(1, -1)
        prediction = model.predict(feature_values)
        return prediction[0] == -1
    except ValueError as e:
        logging.error(f"Error in prediction: {e}")
        return False


def convert_json_to_csv():
    try:
        with open(JSON_DATA_PATH, 'r') as file:
            data = json.load(file)
        df = pd.json_normalize(data)
        df.to_csv(CSV_DATA_PATH, index=False)
        logging.info(f"Data saved as CSV to {CSV_DATA_PATH}")
    except Exception as e:
        logging.error(f"Failed to convert JSON to CSV: {e}")

def get_network_info():
    try:
        ip_info = subprocess.check_output(['ifconfig', INTERFACE], text=True).strip()
        return ip_info
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to get network info for interface {INTERFACE}: {e}", exc_info=True)
        return None
    
def main():
    logging.info("Starting main function")
    try:
        analyzer = NetworkAnalyzer()
        logging.info("Analyzer initialized")

        # Capture packets using the capture_packets method
        packets = analyzer.capture_packets()
        logging.info(f"Captured {len(packets)} packets")

        logging.debug("Starting traffic analysis")
        analyzed_data = analyzer.analyze_traffic(packets)
        logging.info("Traffic analysis completed")

        ip = get_network_info()
        if not ip:
            logging.error(f"Failed to get network info for interface {INTERFACE}")
            return

        with open(JSON_DATA_PATH, 'w') as f:
            json.dump(analyzed_data, f, indent=4)

        logging.info("Packet analysis completed and saved to JSON.")

        convert_json_to_csv()

        network_range = '.'.join(ip.split('.')[:-1]) + '.0/24'
        analyzer.run_nmap(network_range)

    except Exception as e:
        logging.error(f"An unexpected error occurred in main: {e}")
        logging.debug(f"Stack Trace: {traceback.format_exc()}")

    finally:
        logging.info("Main function execution completed")

if __name__ == "__main__":
    logging.basicConfig(filename=LOGGING_PATH, level=logging.DEBUG)
    main()
