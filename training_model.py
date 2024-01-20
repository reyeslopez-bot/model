import json
import logging
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.datasets import load_iris
import joblib
# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Load a sample dataset
data = load_iris()
X, y = data.data, data.target

def train_model():
    # Load network data
    try:
        with open('network_data.json', 'r') as file:
            file_content = file.read()
            if not file_content:
                logging.error("network_data.json is empty.")
                return
            collected_network_data = json.loads(file_content)
    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error: {str(e)}")
        return
    except Exception as e:
        logging.error(f"Error reading network data: {str(e)}")
        return
    
    # Extract features and labels
    X_df = pd.DataFrame([data['features'] for data in collected_network_data])
    y_series = pd.Series([data['anomaly'] for data in collected_network_data])

    if X_df.empty or y_series.empty:
        logging.error("Extracted features or labels are empty.")
        return

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X_df, y_series, test_size=0.2, random_state=42)

    # Train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate the model
    accuracy = model.score(X_test, y_test)
    logging.info(f"Model accuracy: {accuracy}")

    # Save the trained model
    try:
        joblib.dump(model, 'trained_model.pkl')
        logging.info("Model saved with joblib.")
    except Exception as e:
        logging.error(f"Error saving the model with joblib: {str(e)}")

if __name__ == "__main__":
    train_model()
