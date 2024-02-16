import streamlit as st
from streamlit_extras.switch_page_button import switch_page

st.set_page_config(
   page_title="Log In - On Guard",
   page_icon="🤺"
)

st.title(":fencer: On Guard")
def log_in():
    st.subheader("Log In")
    with st.form(key="login", clear_on_submit=True):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        login = st.form_submit_button("Log In")
        if login:
            if username != "TeamVCIS":
                st.error("Wrong username!")
            
            if password != "victory":
                st.error("Wrong password!")
            
            if username == "TeamVCIS" and password == "victory":
                switch_page("monitor-text")

log_in()
