import streamlit as st
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from googletrans import Translator
import smtplib
from email.mime.text import MIMEText

raw_spam_data = pd.read_csv("Phishing_Email.csv")
spam_data = raw_spam_data.where((pd.notnull(raw_spam_data)),"")
spam_data.loc[spam_data["Email Type"] == 'Phishing Email', "Email Type",] = 1
spam_data.loc[spam_data["Email Type"] == 'Safe Email', "Email Type",] = 0

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
user_email = form.text_input("Gmail")
text = form.text_area("Text to analyze")
files = form.file_uploader(label="Upload .txt files", type=["txt", "docx", "odt"], accept_multiple_files=True)
submit_button = form.form_submit_button(label="Submit")

def flag(text):
   text = [text]
   input_data_features = feature_extraction.transform(text)
   prediction = model.predict(input_data_features)
   return prediction

email_text = []
translator = Translator()
txt = ""
file_txt = []

if submit_button:
   if len(text) > 0:
      text = translator.translate(text).text
      if flag(text)[0] == 1:
         txt = ":red[Threat detected in the provided text!]"
         email_text.append("Threat detected in the provided text!")
         email_text.append(text)
         email_text.append("\n")
      else:
         txt = "This text is safe!"

   if len(files) > 0:
      for f in files:
         content = f.getvalue().decode()
         if len(content) == 0:
            file_txt.append(f"{f.name} is empty!")
         else:
            content = translator.translate(content).text
            if flag(content)[0] == 1:
               file_txt.append(f":red[Threat detected in {f.name}!]")
               email_text.append(f"Threat detected in {f.name}!")
               email_text.append(content)
               email_text.append("\n")
            else:
               file_txt.append(f"{f.name} is safe!")

   email_text = "\n".join(email_text)
   msg = MIMEText(email_text)
   msg["From"] = st.secrets["email"]
   msg["To"] = user_email
   msg["Subject"] = "Results from Flagged's text analysis"
   server = smtplib.SMTP('smtp.gmail.com', 587)
   server.starttls()
   server.login(st.secrets["email"], st.secrets["password"])
   server.sendmail(st.secrets["email"], user_email, msg.as_string())
   server.quit()
   st.success("An email containing the results has been sent to your account! (If you don't see it, check your spam folder)")

st.write(txt)
for t in file_txt:
   st.write(t)