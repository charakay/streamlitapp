import streamlit as st
import requests

# Function to check IP details
def check_ip(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90  # You can adjust this to the number of days you want to check against
    }
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        st.error(f"API request failed with status code {response.status_code}")
        return None

# Function to extract relevant information
def extract_ip_info(ip_data):
    abuse_score = ip_data['data']['abuseConfidenceScore']
    country = ip_data['data']['countryCode']
    domain = ip_data['data']['domain']
    return abuse_score, country, domain

# Streamlit app layout
st.title("IP Reputation Checker")
api_key = st.text_input("Enter your AbuseIPDB API key:", type="password")

# Input box for pasting a list of IPs
ip_list = st.text_area("Paste a list of IPs (one per line)")

if ip_list and api_key:
    # Convert the input to a list of IPs
    ip_list = [ip.strip() for ip in ip_list.split('\n') if ip.strip()]
    
    malicious_ips = []
    clean_ips = []
    
    # Iterate over each IP in the list
    with st.spinner("Checking IPs..."):
        for ip in ip_list:
            ip_data = check_ip(ip, api_key)
            if ip_data:
                abuse_score, country, domain = extract_ip_info(ip_data)
                if abuse_score > 0:
                    malicious_ips.append((ip, abuse_score, country, domain))
                else:
                    clean_ips.append((ip, abuse_score, country, domain))
    
    # Display results for malicious IPs
    st.subheader("Malicious IPs")
    if malicious_ips:
        for ip, score, country, domain in malicious_ips:
            st.write(f"{ip} | Abuse Score: {score} | Country: {country} | Domain: {domain}")
    else:
        st.write("No malicious IPs found.")

    # Display results for clean IPs
    st.subheader("Clean IPs")
    if clean_ips:
        for ip, score, country, domain in clean_ips:
            st.write(f"{ip} | Abuse Score: {score} | Country: {country} | Domain: {domain}")
    else:
        st.write("No clean IPs found.")
