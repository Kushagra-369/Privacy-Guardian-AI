import numpy as np
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
import joblib

# ===== DATASET (EXPANDED) =====
# [trackers, cookies, location, camera]
X = np.array([
    [0,0,0,0],
    [1,1,0,0],
    [2,1,1,0],
    [3,1,1,1],
    [5,1,1,1],
    [4,1,0,1],
    [6,1,1,1],
    [2,0,0,0],
    [1,0,0,0],
    [3,1,0,1],
    [4,1,1,0],
    [5,1,0,1],
    [6,1,1,0],
    [2,1,1,1],
])

# risk scores
y = np.array([
    5, 30, 60, 80, 95, 75,
    98, 10, 5, 70, 65, 85, 90, 78
])

# ===== SPLIT =====
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ===== MODEL (BETTER 🔥) =====
model = RandomForestRegressor(n_estimators=100)
model.fit(X_train, y_train)

# ===== ACCURACY CHECK =====
score = model.score(X_test, y_test)
print(f"🔥 Model R² Score: {score:.2f}")

# ===== SAVE =====
joblib.dump(model, "model.pkl")

print("✅ Model trained & saved as model.pkl")