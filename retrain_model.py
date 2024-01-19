import sys
import numpy as np
import pandas as pd
import sklearn
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.linear_model import LogisticRegression
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import argparse

def load_data(file_path):
    df = pd.read_csv(file_path, sep='\s+', names=['proto', 'bytes', 'src_ip', 'src_port', 'dst_ip', 'dst_port'])
    df = df.drop(columns=['proto', 'src_ip', 'dst_ip'])
    df = df.groupby(['src_port', 'dst_port']).size().reset_index(name='frequency')
    return df

def train_test_split(df, test_size=0.2):
    train_df = df.sample(frac=1-test_size, random_state=42)
    test_df = df.drop(train_df.index)
    return train_df, test_df

def preprocess_and_train(train_df, model):
    train_data = train_df.drop(columns=['src_port', 'dst_port', 'frequency'])
    train_labels = train_df[['src_port', 'dst_port', 'frequency']]
    
    scaler = StandardScaler()
    train_data = scaler.fit_transform(train_data)
    
    model.fit(train_data)
    
    return model, scaler

def evaluate_model(model, test_df, scaler):
    test_data = test_df.drop(columns=['src_port', 'dst_port', 'frequency'])
    test_labels = test_df[['src_port', 'dst_port', 'frequency']]
    
    test_data = scaler.transform(test_data)
    
    pred_labels = model.predict(test_data)
    
    print("Classification Report:")
    print(classification_report(test_labels, pred_labels))
    
    print("Confusion Matrix:")
    print(confusion_matrix(test_labels, pred_labels))
    
def detect_anomalies(model, scaler, df):
    data = df.drop(columns=['src_port', 'dst_port', 'frequency'])
    
    data = scaler.transform(data)
    
    pred_labels = model.predict(data)
    
    anomalies = df[pred_labels == -1]
    
    return anomalies

def run_pipeline(file_path, model, test_size=0.2):
    df = load_data(file_path)
    train_df, test_df = train_test_split(df, test_size)
    model, scaler = preprocess_and_train(train_df, model)
    evaluate_model(model, test_df, scaler)
    anomalies = detect_anomalies(model, scaler, df)
    
    return anomalies

def preprocess_and_train(train_df, model):
    # Assume train_df has columns 'features' and 'label'
    train_features = train_df['features']
    train_labels = train_df['label']
    
    scaler = StandardScaler()
    train_features_scaled = scaler.fit_transform(train_features)
    
    model.fit(train_features_scaled, train_labels)
    
    return model, scaler

def evaluate_model(model, test_df, scaler):
    test_features = test_df['features']
    test_labels = test_df['label']
    
    test_features_scaled = scaler.transform(test_features)
    pred_labels = model.predict(test_features_scaled)
    
    print("Classification Report:")
    print(classification_report(test_labels, pred_labels))
    
    print("Confusion Matrix:")
    print(confusion_matrix(test_labels, pred_labels))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", required=True, help="Input file path")
    parser.add_argument("-m", "--model", required=True, choices=['iforest', 'lof', 'logistic', 'svm'], help="Anomaly detection")