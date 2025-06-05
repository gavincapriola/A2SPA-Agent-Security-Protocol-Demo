import streamlit as st

st.set_page_config(page_title="A2SPA Demo", layout="centered")

st.title("🚀 A2SPA is Live on cPanel!")
st.markdown("This page is powered by **Streamlit**, running inside your cPanel Python app.")

if st.button("🎉 Click to Test"):
    st.success("✅ Streamlit is working inside cPanel!")
