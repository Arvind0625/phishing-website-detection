#  Phishing Website Detection using Machine Learning

## About the Project

Phishing attacks are one of the most common cybersecurity threats, where malicious websites imitate legitimate ones to steal sensitive user information. This project presents a Machine Learning-based solution that helps identify phishing websites by analysing URL-based features and predicting whether a website is legitimate or phishing.

The application is built using **Python**, **Flask**, and **Scikit-learn**, providing a simple and interactive web interface for users to test website URLs in real time.

---

## Features

- Detects phishing websites using Machine Learning
- Classifies websites as **Legitimate** or **Phishing**
- Simple and user-friendly web interface
- Instant prediction using a trained ML model
- Lightweight and easy to use

---

## Technologies Used

- Python
- Flask
- Scikit-learn
- Pandas
- NumPy
- HTML
- CSS

---

## Project Structure

```
phishing-website-detection/
│
├── app.py
├── train_model.py
├── clean_dataset.py
├── dataset.csv
├── newdataset.csv
├── requirements.txt
├── models/
│   └── phishing_model.pkl
├── static/
│   └── style.css
├── templates/
│   └── index.html
└── README.md
```

---

## Getting Started

### Clone the Repository

```bash
git clone https://github.com/Arvind0625/phishing-website-detection.git
```

### Navigate to the Project Directory

```bash
cd phishing-website-detection
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Application

```bash
python app.py
```

Open your browser and visit:

```
http://127.0.0.1:5000
```

---

## How It Works

1. The user enters a website URL through the web application.
2. The application extracts the required URL features.
3. The trained Machine Learning model processes the extracted features.
4. The model predicts whether the website is **Legitimate** or **Phishing**.
5. The prediction is displayed instantly to the user.

---

## Model

The project uses a trained Machine Learning model to classify websites based on URL-related features. The model is trained on a phishing website dataset and integrated into the Flask application to provide fast and reliable predictions.

---

## Future Enhancements

- Improve prediction performance using additional features and datasets.
- Deploy the application on a cloud platform.
- Add real-time URL scanning.
- Develop a browser extension for instant phishing detection.
- Integrate threat intelligence APIs for enhanced security.

---

## Author

**Arvind R**

B.Tech Computer Science Engineering Student