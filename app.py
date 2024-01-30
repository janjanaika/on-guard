import streamlit as st
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from googletrans import Translator

raw_spam_data = pd.read_csv("Phishing_Email.csv")
spam_data = raw_spam_data.where((pd.notnull(raw_spam_data)),"")
#spam_data.loc[spam_data["Category"] == 'spam', "Category",] = 0
#spam_data.loc[spam_data["Category"] == 'ham', "Category",] = 1

spam_data.loc[spam_data["Email Type"] == 'Phishing Email', "Email Type",] = 0
spam_data.loc[spam_data["Email Type"] == 'Safe Email', "Email Type",] = 1

#X = spam_data["Message"]
#y = spam_data["Category"]

X = spam_data["Email Text"]
y = spam_data["Email Type"]


X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=1)

feature_extraction = TfidfVectorizer(min_df=1, stop_words='english')

X_train_features = feature_extraction.fit_transform(X_train)
X_test_features = feature_extraction.transform(X_val)

y_train = y_train.astype('int')
Y_test = y_val.astype('int')
model = LogisticRegression()
model.fit(X_train_features, y_train)

form = st.form(key="my_form")
text = form.text_area("Text to analyze")
files = form.file_uploader(label="Upload .txt files", type=["txt", "docx", "odt"], accept_multiple_files=True)
submit_button = form.form_submit_button(label="Submit")

def flag(text):
   text = [text]
   input_data_features = feature_extraction.transform(text)
   prediction = model.predict(input_data_features)
   return prediction

translator = Translator()
txt = ""
if submit_button and len(text) > 0:
   text = translator.translate(text).text
   if flag(text)[0] == 0:
      txt = "Threat detected in text!"
   else:
      txt = "This text is safe!"

file_txt = []

if len(files) > 0:
   for f in files:
      content = f.getvalue().decode()
      if len(content) == 0:
         file_txt.append(f"{f.name} is empty!")
      else:
         content = content
         content = translator.translate(content).text
         if flag(content)[0] == 0:
            file_txt.append(f"Threat detected in {f.name}!")
         else:
            file_txt.append(f"{f.name} is safe!")

st.write(txt)
for t in file_txt:
   st.write(t)