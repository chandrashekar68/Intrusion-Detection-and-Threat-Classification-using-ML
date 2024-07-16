# Main Python Code for the ML Model used for Intrusion Detection and Threat Classification

import numpy as np
import pandas as pd
import os
import tensorflow as tf

path = "MachineLearningCVE/"
csv_files = []
dataset = []

# Getting Training Data As CSV Files
def get_training_data():
    for root, directories, files in os.walk(path):
        for file in files:
            csv_files.append(os.path.join(root, file))

    return [pd.read_csv(f) for f in csv_files]

# Concat Valid Data(Valid Data Means Either the data is a DataFrame or a Series Object)
def concat_valid_data():
    global dataset
    # Assuming dataset is a list containing DataFrames or Series objects
    valid_data = [d for d in dataset if isinstance(d, (pd.DataFrame, pd.Series))]

    # Concatenate the valid DataFrames or Series objects
    if valid_data:
        dataset = pd.concat(valid_data).drop_duplicates(keep=False)
        dataset.reset_index(drop=True, inplace=True)
        print("Combined dataset created successfully.")
    else:
        print("No valid data found in the dataset list.")

# Clean and Preprocess the Dataset
def clean_dataset():
    global dataset
    # Removing whitespaces in column names.
    col_names = [col.replace(' ', '') for col in dataset.columns]
    dataset.columns = col_names

    # Removing the weird characters and making the labels a valid string suitable for classification
    import re # Regular Expression

    label_names = [re.sub("[^a-zA-Z ]+", "", l) for l in dataset['Label'].unique()]
    label_names = [re.sub("[\s\s]", '_', l) for l in label_names]
    label_names = [l.replace("__", "_") for l in label_names]

    prev_labels = dataset['Label'].unique()

    # Replacing Previous labels with the cleaned labels
    for i in range(len(label_names)):
        dataset['Label'] = dataset['Label'].replace({prev_labels[i]: label_names[i]})

    # Since only a small number of rows contain NULL value, We will remove them
    dataset.dropna(inplace=True)

    # Removing label column for now because it has string values
    label = dataset['Label']
    dataset = dataset.loc[:, dataset.columns != 'Label'].astype('float64')

    # Replacing infinite values with NaN values.
    dataset = dataset.replace([np.inf, -np.inf], np.nan)

    # Adding the Labels column back again
    dataset = dataset.merge(label, how='outer', left_index=True, right_index=True)

    # Removing new NaN values.
    dataset.dropna(inplace=True)

    return label_names

# Scaling The Data Using RobustScaler
def scale_dataset():
    from sklearn.preprocessing import RobustScaler

    # Splitting dataset into features and labels.
    labels = dataset['Label']
    features = dataset.loc[:, dataset.columns != 'Label'].astype('float64')

    scaler = RobustScaler()
    scaler.fit(features)

    features = scaler.transform(features)
    return labels, features

# Encoding the label names as Integers
def encode_label_names(labels):
    from sklearn.preprocessing import LabelEncoder

    LE = LabelEncoder()

    LE.fit(labels)
    labels = LE.transform(labels)

# Split the data into training and testing sets
def split_data(features, labels):
    from sklearn.model_selection import train_test_split
    
    # For this we will use sklearn function train_test_split().
    # 80-20 split
    return train_test_split(features, labels, test_size=0.2)

# Create the model
def build_model():

    model = tf.keras.models.Sequential([
        tf.keras.layers.Flatten(input_shape=(78,)),
        tf.keras.layers.Dense(67, activation='relu'),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(15, activation='softmax')
    ])

    return model

# Compile the model
def compile_model(model):
    # For learning rate optimization we used Adam optimizer.
    # Loss function used is sparse categorical crossentropy, which is standard for multiclass 
    # classification problems.

    model.compile(optimizer='adam',
                  loss='sparse_categorical_crossentropy',
                  metrics=['accuracy'])
    
    return model

# Fit the model (Train it, requires a long time)
def fit_model(model, features_train, labels_train):
    model.fit(features_train, labels_train, epochs=5)
    return model

def evaluate_model(model, features_test, labels_test):
    # Evaluating model accuracy.
    model.evaluate(features_test, labels_test, verbose=2)

# Predict The Attacks
def predict_attack(model, label_names, features):
    # Define a dictionary mapping attack labels to their severity levels
    severity_mapping = {
        'BENIGN': 'Low', 
        'DDoS': 'High', 
        'PortScan': 'Medium', 
        'Bot': 'High', 
        'Infiltration': 'High',
        'Web_Attack_Brute_Force': 'Medium', 
        'Web_Attack_XSS': 'Medium', 
        'Web_Attack_Sql_Injection': 'High',
        'FTPPatator': 'Medium', 
        'SSHPatator': 'Medium', 
        'DoS_slowloris': 'High', 
        'DoS_Slowhttptest': 'High',
        'DoS_Hulk': 'High', 
        'DoS_GoldenEye': 'High', 
        'Heartbleed': 'High'
    }

    predictions = model.predict(features)
    predicted_indices = predictions.argmax(axis=1)
    predicted_labels = [label_names[i] for i in predicted_indices]
    severity_levels = [severity_mapping[label] for label in predicted_labels]

    predicted_attacks_with_severity = zip(predicted_labels, severity_levels)
    for attack, severity in predicted_attacks_with_severity:
        print(f"Predicted Attack: {attack}, Severity: {severity}")

# Save Dataset and Model
def save_dataset_and_model(dataset, model):
    dataset.to_csv("cleaned_dataset.csv", index=False)

    model.save('trained_model.keras')

# Load Dataset and Model
def load_dataset_and_model():
    dataset = pd.read_csv('cleaned_dataset.csv')

    model = tf.keras.models.load_model('trained_model.keras')

    return dataset, model

def get_real_time_data():

    from snortl import RealTimeData

    real_time_data_instance = RealTimeData()

    real_time_data = real_time_data_instance.get_cleaned_real_time_data()

    real_time_df = pd.DataFrame([real_time_data])

    labels = real_time_df['Label']

    features = real_time_df.loc[:, real_time_df.columns != 'Label'].astype('float64')

    from sklearn.preprocessing import LabelEncoder

    LE = LabelEncoder()

    LE.fit(labels)
    labels = LE.transform(labels)

    return labels, features

if __name__ == "__main__":
    # dataset = get_training_data()

    # concat_valid_data()

    # label_names = clean_dataset()

    # labels, features = scale_dataset()

    # labels = encode_label_names(labels)

    # features_train, features_test, labels_train, labels_test = split_data(features, labels)

    # model = build_model()

    # model = compile_model(model)

    # model = fit_model(model, features_train, labels_train)

    # evaluate_model(model, features_test, labels_test)

    # save_dataset_and_model(dataset, model)

    ##

    dataset, model = load_dataset_and_model()

    label_names = dataset['Label'].unique()

    labels, features = get_real_time_data()
    
    predict_attack(model, label_names, features)
