import streamlit as st
import scanner 

st.title("Network Scanner")
subnet = st.text_input("Enter subnet/IP:", "192.168.0.0/24")

if st.button("Scan"):
    with st.spinner(f"Scanning..."):
        results = scanner.Scan_Network(subnet)
        
    st.success("Scan Complete!")
    st.write("### Result:")
    st.write(results)


