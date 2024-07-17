import pandas as pd  # data processing, CSV file I/O (e.g. pd.read_csv)
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from sklearn.feature_extraction.text import TfidfVectorizer
from django.http import JsonResponse
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import hashlib
import requests

MODEL_PATH = 'path/to/your/model.joblib'
DATASET_PATH = 'path/to/your/dataset_phishing.csv'


def load_dataset(file_path):
    try:
        return pd.read_csv(file_path)
    except FileNotFoundError:
        return None


def train_model(X, y):
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    return clf


@csrf_exempt
def index(request):
    result = " "  # Default value
    DATASET_PATH = "C:/records/env/ml/ml/static/dataset_phishing.csv"
    if request.method == 'POST':
        url = request.POST.get('url')

        # Load your dataset
        df = load_dataset(DATASET_PATH)

        if df is None:
            return JsonResponse({'error': 'Dataset not found'}, status=400)

        X = df.drop('status', axis=1)
        y = df['status']

        # Extract features from URLs using TF-IDF
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(X['url'])

        # Check if the model is already trained
        if not hasattr(index, 'model'):
            # Train the model if not trained
            index.model = train_model(X, y)

        # Extract features from the user input URL using the same TF-IDF vectorizer
        user_input_features = vectorizer.transform([url])

        # Make a prediction
        prediction = index.model.predict(user_input_features)

        # Interpret the prediction
        result = "Not Safe" if prediction[0] == 1 else "Safe"
        print(f"{result}: The provided URL is classified as {result}.")

    return render(request, 'phishing.html', {'url': result})


def void(request):
    return render(request, 'index.html')


def spamMail(request):
    mail = " "  # Initialize mail with an empty string

    if request.method == 'POST':
        # Get the list of email texts from the HTML form
        email_texts = request.POST.getlist('email_text')
        print(email_texts)
        # Load the spam dataset
        data = pd.read_csv('C:/records/env/ml/ml/static/spam.csv')

        # Check the columns in your dataset
        print(data.columns)

        # Assume that your dataset has a column named 'Category' for labels
        # If your dataset uses different column names, please modify accordingly
        X = data.Message
        y = data.Category

        # Convert labels to binary values (1 for 'spam' and 0 for 'ham')
        y = y.apply(lambda x: 1 if x == 'spam' else 0)

        # Split the data into training and testing sets
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42)

        # Create a pipeline with CountVectorizer and Naive Bayes
        clf = Pipeline([
            ('vectorizer', CountVectorizer()),
            ('nb', MultinomialNB())
        ])

        # Train the model
        clf.fit(X_train, y_train)

        # Make predictions
        predictions = clf.predict(email_texts)

        # Display predictions (you may want to pass this information to the HTML template)
        if predictions[0] == 0:
            mail = "HAM"
        else:
            mail = "SPAM"
    return render(request, 'spam.html', {'mail': mail})


def check_pwned_password(password):
    sha_password = hashlib.sha1(password.encode()).hexdigest()
    sha_prefix = sha_password[0:5]
    sha_postfix = sha_password[5:].upper()

    url = 'https://api.pwnedpasswords.com/range/' + sha_prefix

    payload = {}
    headers = {}
    response = requests.request('GET', url, headers=headers, data=payload)

    pwnd_list = response.text.split("\r\n")

    for pwnd_pass in pwnd_list:
        pwnd_hash = pwnd_pass.split(":")
        pwnd_suffix = pwnd_hash[0]

        if pwnd_suffix == sha_postfix:
            return int(pwnd_hash[1])  # Password found in the compromised list

    return 0


def passShield(request):
    check = " "
    if request.method == 'POST':
        password_to_check = request.POST.get('pass')
        compromised_count = check_pwned_password(password_to_check)

        if compromised_count == 0:
            check = "Good news! The password has not been compromised."
        else:
            check = f"Warning! The password has been compromised {compromised_count}"

    return render(request, 'pass.html', {'check': check})
