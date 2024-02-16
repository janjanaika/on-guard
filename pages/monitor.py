import streamlit as st
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from googletrans import Translator
import smtplib
from email.mime.text import MIMEText
import re
import requests
import easyocr as ocr
from PIL import Image

st.set_page_config(
   page_title="On Guard",
   page_icon="🤺"
)

@st.cache_data(show_spinner="Loading data...")
def load_data():
   return pd.read_csv("Phishing_Email.csv")

@st.cache_resource(show_spinner="Loading the image reader...")
def load_model():
   return ocr.Reader(["en"], model_storage_directory=".")

st.title(":fencer: On Guard")

with st.form(key="my_form", clear_on_submit=True):
   text = st.text_area("Text to analyze")
   txt_files = st.file_uploader(label="Upload .txt files", type=["txt"], accept_multiple_files=True)
   images = st.file_uploader(label="Upload images", type=["png", "jpg", "jpeg"], accept_multiple_files=True)
   user_email = st.text_input("(Recommended) Send alerts to:", placeholder="juandelacruz@gmail.com")
   submit_button = st.form_submit_button(label="Monitor my child's conversations!")

raw_spam_data = load_data()
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

def detect(text):
   text = [text]
   input_data_features = feature_extraction.transform(text)
   prediction = model.predict(input_data_features)
   return prediction

notif_text = []
translator = Translator()
reader = load_model()
txt = ""
file_results = []
img_results = []

if submit_button:
   with st.spinner("Processing your input..."):
      if len(text) == 0 or text.isspace():
         txt = "The provided text is empty!"
      else:
         text = translator.translate(text).text
         if detect(text)[0] == 1:
            txt = ":red[Threat detected in the provided text!]"
            notif_text.append("Threat detected in the provided text!")
            notif_text.append(text)
            notif_text.append("\n")
         else:
            txt = ":green[Looks like the provided text is safe!]"

      if len(txt_files) > 0:
         for f in txt_files:
            content = f.getvalue().decode()
            if len(content) == 0 or content.isspace():
               file_results.append(f"{f.name} is empty!")
            else:
               content = translator.translate(content).text
               if detect(content)[0] == 1:
                  file_results.append(f":red[Threat detected in {f.name}!]")
                  notif_text.append(f"Threat detected in {f.name}!")
                  notif_text.append(content)
                  notif_text.append("\n")
               else:
                  file_results.append(f":green[Looks like {f.name} is safe!]")

      if len(images) > 0:
         for img in images:
            input_image = Image.open(img)
            result = reader.readtext(np.array(input_image))
            img_text = []

            for text in result:
               img_text.append(text[1])
            
            if len(img_text) == 0:
               file_results.append(f"The AI can't see any text in {img.name}.")
            else:
               img_content = " ".join(img_text)
               img_content = translator.translate(img_content).text
               if detect(img_content)[0] == 1:
                  file_results.append(f":red[Threat detected in {img.name}!]")
                  notif_text.append(f"Threat detected in {img.name}!")
                  notif_text.append(img_content)
                  notif_text.append("\n")
               else:
                  file_results.append(f":green[Looks like {img.name} is safe!]")

   email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
   if re.fullmatch(email_pattern, user_email):
      notif_text = "\n".join(notif_text)
      msg = MIMEText(notif_text)
      msg["From"] = st.secrets["email"]
      msg["To"] = user_email
      msg["Subject"] = "Results from On Guard's text analysis"
      server = smtplib.SMTP('smtp.gmail.com', 587)
      server.starttls()
      server.login(st.secrets["email"], st.secrets["password"])
      server.sendmail(st.secrets["email"], user_email, msg.as_string())
      server.quit()
      if len(notif_text) > 0:
         st.error("There was a threat in your provided file(s)! More details will be sent through your email. If you don't see it, check your spam folder.")
      elif len(txt_files) > 0 and len(notif_text) == 0:
         st.success("Good news! Looks like all of your files are safe!")

st.write(txt)
for f in file_results:
   st.write(f)

for i in img_results:
   st.write(i)
