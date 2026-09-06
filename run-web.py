<<<<<<< HEAD
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


=======
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


>>>>>>> 09d185048b1dee58b04e5828b56b5306a9c0a793
