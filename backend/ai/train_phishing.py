import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# ===== LOAD DATA (MISSING THA 💀) =====
df = pd.read_csv("phishing.csv")

# ===== CLEAN COLUMN NAMES =====
df.columns = df.columns.str.strip()

print("Columns:", df.columns)

# ===== FEATURE SELECTION =====
X = pd.DataFrame()

X["url_length"] = df.get("URL_Length", df.iloc[:, 0])
X["num_dots"] = df.get("having_Sub_Domain", df.iloc[:, 1])
X["has_https"] = df.get("SSLfinal_State", df.iloc[:, 2])
X["has_at_symbol"] = df.get("having_At_Symbol", df.iloc[:, 3])
X["num_hyphens"] = df.get("Prefix_Suffix", df.iloc[:, 4])
X["is_ip"] = df.get("having_IP_Address", df.iloc[:, 5])
X["has_suspicious_word"] = df.get("URL_of_Anchor", df.iloc[:, 6])

y = df.get("Result", df.iloc[:, -1])

# ===== TRAIN =====
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

accuracy = model.score(X_test, y_test)
print(f"🔥 Model Accuracy: {accuracy * 100:.2f}%")

joblib.dump(model, "phishing_model.pkl")

print("✅ Model trained correctly")