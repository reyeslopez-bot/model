import json
import logging
import pandas as pd
from sklearn.model_selection import train_test_split
import tensorflow as tf
import os
from sklearn.preprocessing import StandardScaler, LabelEncoder

def preprocess_data(data):
    # Convert to DataFrame
    df = pd.DataFrame(data)
    
    # Extract features and target
    X = pd.json_normalize(df['features'])
    y = df['anomaly']

    # Convert data types
    X = X.apply(pd.to_numeric, errors='coerce')
    y = LabelEncoder().fit_transform(y)

    # Fill missing values if any
    X.fillna(0, inplace=True)

    # Normalize features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    return X_scaled, y

def train_model():
    JSON_DATA_PATH = '/Users/apikorus/model/network_data.json'

    if not os.path.exists(JSON_DATA_PATH) or os.stat(JSON_DATA_PATH).st_size == 0:
        logging.error(f"{JSON_DATA_PATH} is missing or empty.")
        return
    
    try:
        with open(JSON_DATA_PATH, 'r') as file:
            collected_network_data = json.load(file)
    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error: {str(e)}")
        return
    except Exception as e:
        logging.error(f"Error reading network data: {str(e)}")
        return

    X, y = preprocess_data(collected_network_data)

    # Split the data
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Neural network model
    model = tf.keras.models.Sequential([
        tf.keras.layers.Dense(64, activation='relu', input_shape=(X_train.shape[1],)),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')  # Using sigmoid for binary classification
    ])

    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

    # Train the model
    model.fit(X_train, y_train, epochs=10, validation_data=(X_test, y_test))

    # Save the model
    model.save('trained_model')

if __name__ == "__main__":
    train_model()
