import joblib

from pathlib import Path


MODELS_DIR = Path("models")


print("=" * 80)
print("MODEL INSPECTION")
print("=" * 80)


models = [
    "random_forest_binary_cicids2017.pkl",
    "random_forest_multiclass_cicids2017.pkl",
    "xgboost_binary_cicids2017.pkl",
    "xgboost_multiclass_cicids2017.pkl"
]


for filename in models:

    print()
    print("-" * 80)
    print("MODEL:", filename)

    model = joblib.load(MODELS_DIR / filename)

    print("Type:", type(model).__name__)

    print("Classes:")
    print(getattr(model, "classes_", "N/A"))

    print("Number of features:")
    print(len(getattr(model, "feature_names_in_", [])))

    if hasattr(model, "feature_names_in_"):

        print()
        print("FEATURE NAMES:")

        for i, feature in enumerate(model.feature_names_in_, start=1):

            print(f"{i:02d}. {feature}")


print()
print("=" * 80)
print("MODEL INSPECTION FINISHED")
print("=" * 80)