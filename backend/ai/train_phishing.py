import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib

# ===== LOAD WITHOUT HEADERS =====
df = pd.read_csv("phishing.csv")
df = df.select_dtypes(include=['number'])
# ===== FEATURES & LABEL =====
X = df.iloc[:, :-1]   # all except last column
y = df.iloc[:, -1]    # last column = label

# ===== SPLIT =====
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ===== MODEL =====
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# ===== ACCURACY CHECK (IMPORTANT 🔥)
accuracy = model.score(X_test, y_test)
print(f"🔥 Model Accuracy: {accuracy * 100:.2f}%")

# ===== SAVE =====
joblib.dump(model, "phishing_model.pkl")

print("✅ Phishing model trained & saved")