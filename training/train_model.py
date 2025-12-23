import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

# -----------------------------
# 1. Load dataset
# -----------------------------
columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count",
    "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"
]

train_df = pd.read_csv("data/KDDTrain+.txt", names=columns)

# -----------------------------
# 2. Binary classification
# -----------------------------
train_df["label"] = train_df["label"].apply(
    lambda x: "normal" if x == "normal" else "attack"
)

# -----------------------------
# 3. Encode categorical data
# -----------------------------
encoder = LabelEncoder()
for col in ["protocol_type", "service", "flag"]:
    train_df[col] = encoder.fit_transform(train_df[col])

# -----------------------------
# 4. Split features & labels
# -----------------------------
X = train_df.drop(["label", "difficulty"], axis=1)
y = train_df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# -----------------------------
# 5. Train model
# -----------------------------
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# -----------------------------
# 6. Evaluate model
# -----------------------------
y_pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))

# -----------------------------
# 7. Save model
# -----------------------------
joblib.dump(model, "models/rf_ids_model.pkl")
print("Model saved successfully!")
