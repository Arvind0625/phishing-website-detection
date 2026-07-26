import pandas as pd

# Load original dataset
data = pd.read_csv("dataset.csv")

# Keep only URL and label
cleaned_data = data[["URL", "label"]]

cleaned_data = cleaned_data.drop_duplicates()

# Save new dataset
cleaned_data.to_csv("newdataset.csv", index=False)

print("New dataset created successfully!")
print(cleaned_data.head())
