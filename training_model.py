import json
import pickle
import logging
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.datasets import load_iris
# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Define global constants
INTERFACE = 'en0'
DURATION = 30

# Load a sample dataset
data = load_iris()
X, y = data.data, data.target

def train_model():
    X_train, X_test, y_train, y_test = train_test_split(X_df, y_series, test_size=0.2, stratify=y_series, random_state=42)

    model = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    accuracy = model.score(X_test, y_test)
    logging.info(f"Model accuracy: {accuracy}")

    # Save the trained model
    with open('trained_model.pickle', 'wb') as file:
        pickle.dump(model, file)
    logging.info("Model saved.")
    try:
        # Read in the collected network data
        with open('network_data.json', 'r') as file:
            collected_network_data = json.load(file)

        # Check if network data is empty
        if not collected_network_data:
            logging.error("No data found in network_data.json. Make sure the file has data and is not empty.")
            return

        # Extract features and labels
        X = [data['features'] for data in collected_network_data]
        y = [data['anomaly'] for data in collected_network_data]

        # Convert lists to pandas DataFrame and Series
        X_df = pd.DataFrame(X)
        y_series = pd.Series(y)

        # Check if DataFrame is empty
        if X_df.empty or y_series.empty:
            logging.error("Extracted features or labels are empty. Check the data structure and content of network_data.json.")
            return

        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(X_df, y_series, test_size=0.2, random_state=42)

        # Train the model using the training data
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # Evaluate the model's performance on the testing data
        accuracy = model.score(X_test, y_test)
        logging.info(f"Model accuracy: {accuracy}")

        # Save the trained model
        with open('trained_model.pickle', 'wb') as file:
            pickle.dump(model, file)
        logging.info("Model saved.")

    except Exception as e:
        logging.error(f"Error in training the model: {str(e)}")