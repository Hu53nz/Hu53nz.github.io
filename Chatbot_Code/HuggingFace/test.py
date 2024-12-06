import os  
import requests  
import streamlit as st  
from dotenv import load_dotenv  
from collections import defaultdict  
import time  
import json  
import psutil  
  
# Load environment variables from .env file  
load_dotenv()  
  
# Configuration  
AZURE_OPENAI_API_KEY = os.environ["AZURE_OPENAI_APIKEY"]  
AZURE_OPENAI_ENDPOINT = os.environ["AZURE_OPENAI_ENDPOINT"] + "openai/deployments/gpt-4o/chat/completions?api-version=2024-08-01-preview" 
#"openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-02-15-preview"

RATE_LIMIT_PER_MINUTE = 5  
BLOCK_DURATION = 60 * 5  # Block for 5 minutes after detecting DoS  
MAX_REQUESTS_BEFORE_BLOCK = 3  # Number of rate limit breaches before blocking  
LOG_FILE = "request_logs.txt"  # File to log the requests in text format  
BLOCK_DATA_FILE = "block_data.json"  # File to store blocked IPs and request counts  
REQUESTS_PER_SET = 10  # Number of requests per set for aggregation  
  
# Metrics tracking for visualization  
if 'failed_requests' not in st.session_state:  
    st.session_state.failed_requests = 0  
if 'successful_requests' not in st.session_state:  
    st.session_state.successful_requests = 0  
if 'rate_limit_warnings' not in st.session_state:  
    st.session_state.rate_limit_warnings = defaultdict(int)  
if 'total_requests' not in st.session_state:  
    st.session_state.total_requests = 0  
if 'blocked_ips_count' not in st.session_state:  
    st.session_state.blocked_ips_count = 0  
if 'cpu_utilization_with_rl' not in st.session_state:  
    st.session_state.cpu_utilization_with_rl = []  
if 'cpu_utilization_without_rl' not in st.session_state:  
    st.session_state.cpu_utilization_without_rl = []  
if 'response_time_with_rl' not in st.session_state:  
    st.session_state.response_time_with_rl = []  
if 'response_time_without_rl' not in st.session_state:  
    st.session_state.response_time_without_rl = []  
if 'user_block_count' not in st.session_state:  
    st.session_state.user_block_count = defaultdict(int)  # To track how many times each user was blocked  
  
# Function to save blocked IPs and request counts to a file  
def save_block_data():  
    block_data = {  
        "blocked_ips": st.session_state.blocked_ips,  
        "request_count": {ip: list(times) for ip, times in st.session_state.request_count.items()},  
        "rate_limit_violations": dict(st.session_state.rate_limit_violations),  
        "user_block_count": dict(st.session_state.user_block_count)  
    }  
    with open(BLOCK_DATA_FILE, "w") as file:  
        json.dump(block_data, file)  
  
# Function to load blocked IPs and request counts from a file  
def load_block_data():  
    if os.path.exists(BLOCK_DATA_FILE):  
        with open(BLOCK_DATA_FILE, "r") as file:  
            block_data = json.load(file)  
            st.session_state.blocked_ips = block_data.get("blocked_ips", {})  
            st.session_state.request_count = defaultdict(list, block_data.get("request_count", {}))  
            st.session_state.rate_limit_violations = defaultdict(int, block_data.get("rate_limit_violations", {}))  
            st.session_state.user_block_count = defaultdict(int, block_data.get("user_block_count", {}))  
    else:  
        st.session_state.blocked_ips = {}  
        st.session_state.request_count = defaultdict(list)  
        st.session_state.rate_limit_violations = defaultdict(int)  
        st.session_state.user_block_count = defaultdict(int)  
  
# Function to log requests and block information in a text file  
def log_request(ip, status, message=""):  
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))  
    log_message = f"{current_time} - IP: {ip} - Status: {status} - {message}\n"  
    with open(LOG_FILE, mode="a") as file:  
        file.write(log_message)  
  
# Function to send request to Azure OpenAI  
def get_openai_response(user_message):  
    headers = {  
        "Content-Type": "application/json",  
        "api-key": AZURE_OPENAI_API_KEY,  
    }  
  
    # Construct the payload  
    payload = {  
        "messages": [  
            {  
                "role": "system",  
                "content": [  
                    {  
                        "type": "text",  
                        "text": "You are an AI assistant that helps people find information."  
                    }  
                ]  
            },  
            {  
                "role": "user",  
                "content": [  
                    {  
                        "type": "text",  
                        "text": user_message  
                    }  
                ]  
            }  
        ],  
        "temperature": 0.7,  
        "top_p": 0.95,  
        "max_tokens": 800  
    }  
  
    # Send the request  
    try:  
        # Measure CPU utilization over a fixed interval before sending the request  
        psutil.cpu_percent(interval=None)  # Discard the first call  
        start_time = time.time()  
  
        response = requests.post(AZURE_OPENAI_ENDPOINT, headers=headers, json=payload)  
        response.raise_for_status()  
  
        response_time = time.time() - start_time  
        # Measure CPU utilization over a fixed interval after receiving the response  
        cpu_utilization = psutil.cpu_percent(interval=1)  
  
        st.session_state.total_requests += 1  # Track total requests  
        return response.json()['choices'][0]['message']['content'], response_time, cpu_utilization  
    except requests.RequestException as e:  
        st.error(f"Error making the request: {e}")  
        st.session_state.failed_requests += 1  # Track failed requests  
        st.session_state.total_requests += 1  # Track total requests  
        return None, None, None  
  
# Load block data when the app starts  
load_block_data()  
  
# Streamlit UI  
st.title("Chatbot with Rate Limiting and DoS Protection")  
  
# Toggle for enabling or disabling rate limiting and DoS protection  
use_rate_limiting = st.checkbox("Enable Rate Limiting and DoS Protection", value=True)  
  
user_input = st.text_area("Enter multiple queries (separated by newlines):", height=200)  
# Simulate user IP (for testing purposes)  
user_ip = st.session_state.get("user_ip", "127.0.0.1")  
  
# Check if the user is blocked  
current_time = time.time()  
if use_rate_limiting:  
    if user_ip in st.session_state.blocked_ips and current_time < st.session_state.blocked_ips[user_ip]:  
        st.error("Potential DoS attack detected. Your IP is temporarily blocked.")  
        unblock_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.session_state.blocked_ips[user_ip]))  
        log_request(user_ip, "Blocked", f"Blocked until {unblock_time}")  
    else:  
        # Clean up old requests older than 60 seconds  
        st.session_state.request_count[user_ip] = [req for req in st.session_state.request_count[user_ip] if current_time - req < 60]  
  
        # Handle normal user input  
        if user_input:  
            queries = user_input.split("\n")  # Split the input into individual queries  
            for query in queries:  
                if query.strip():  
                    # Check rate limit  
                    if len(st.session_state.request_count[user_ip]) >= RATE_LIMIT_PER_MINUTE:  
                        st.session_state.rate_limit_warnings[user_ip] += 1  
                        if st.session_state.rate_limit_warnings[user_ip] == 1:  
                            # First breach: Warn and stop  
                            st.warning("Rate limit exceeded. Please wait 2 seconds before sending more queries.")  
                            log_request(user_ip, "Rate limit exceeded", f"User input: {query.strip()}")  
                            break  
                        elif st.session_state.rate_limit_warnings[user_ip] == 2:  
                            # Second breach: Warn and stop again  
                            st.warning("Rate limit exceeded again. Please wait before sending more queries.")  
                            log_request(user_ip, "Rate limit exceeded again", f"User input: {query.strip()}")  
                            break  
                        elif st.session_state.rate_limit_warnings[user_ip] >= 3:  
                            # Third breach: Block the user for BLOCK_DURATION  
                            st.session_state.blocked_ips[user_ip] = current_time + BLOCK_DURATION  
                            st.session_state.blocked_ips_count += 1  # Track blocked IPs  
                            st.session_state.user_block_count[user_ip] += 1  # Increment user block count  
                            if st.session_state.user_block_count[user_ip] >= 3:  
                                # Permanently block the user  
                                st.session_state.blocked_ips[user_ip] = float('inf')  
                                st.error("You have been permanently blocked due to repeated rate limit violations.")  
                                log_request(user_ip, "Permanently Blocked", "User has been permanently blocked.")  
                            else:  
                                unblock_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.session_state.blocked_ips[user_ip]))  
                                st.error(f"Potential DoS attack detected. Your IP is temporarily blocked until {unblock_time}.")  
                                log_request(user_ip, "Blocked", f"Blocked until {unblock_time}")  
                            save_block_data()  
                            break  
                    else:  
                        st.session_state.request_count[user_ip].append(current_time)  
                        response, response_time, cpu_utilization = get_openai_response(query.strip())  
                        if response:  
                            st.text(f"Bot: {response}")  
                            st.session_state.successful_requests += 1  # Track successful requests  
                            st.session_state.cpu_utilization_with_rl.append(cpu_utilization)  
                            st.session_state.response_time_with_rl.append(response_time)  
                        log_request(user_ip, "Success", f"User input: {query.strip()}")  
else:  
    # Handle user input without rate limiting  
    if user_input:  
        queries = user_input.split("\n")  # Split the input into individual queries  
        for query in queries:  
            if query.strip():  
                response, response_time, cpu_utilization = get_openai_response(query.strip())  
                if response:  
                    st.text(f"Bot: {response}")  
                    st.session_state.successful_requests += 1  # Track successful requests  
                    st.session_state.cpu_utilization_without_rl.append(cpu_utilization)  
                    st.session_state.response_time_without_rl.append(response_time)  
                log_request(user_ip, "Success", f"User input: {query.strip()}")  
  
# Show Blocked Status  
if st.button("Check Blocked Status"):  
    current_time = time.time()  
    if user_ip in st.session_state.blocked_ips and current_time < st.session_state.blocked_ips[user_ip]:  
        st.write({  
            "blocked": True,  
            "unblock_time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(st.session_state.blocked_ips[user_ip]))  
        })  
    elif user_ip in st.session_state.blocked_ips and st.session_state.blocked_ips[user_ip] == float('inf'):  
        st.write({  
            "blocked": True,  
            "unblock_time": "Permanently blocked"  
        })  
    else:  
        st.write({"blocked": False})  
  
# Show user block count  
st.write(f"User has been blocked {st.session_state.user_block_count[user_ip]} times after hitting rate limit warnings.")  
  
# Function to calculate total CPU utilization for a set of requests
def aggregate_total_metrics(metrics, set_size):
    aggregated = []
    for i in range(0, len(metrics), set_size):
        set_metrics = metrics[i:i + set_size]
        if set_metrics:
            aggregated.append(sum(set_metrics))  # Total CPU utilization for the set
    return aggregated

# Function to calculate average metrics for a set (used for response times)
def aggregate_metrics(metrics, set_size):
    aggregated = []
    for i in range(0, len(metrics), set_size):
        set_metrics = metrics[i:i + set_size]
        if set_metrics:
            aggregated.append(sum(set_metrics) / len(set_metrics))  # Average for the set
    return aggregated


  
# Visualizations
st.header("Metrics Visualization")

# CPU Utilization Bar Graph (Total CPU Utilization)
st.subheader("Total CPU Utilization Per Set of Requests")
cpu_utilization_with_rl = aggregate_total_metrics(st.session_state.cpu_utilization_with_rl, REQUESTS_PER_SET)
cpu_utilization_without_rl = aggregate_total_metrics(st.session_state.cpu_utilization_without_rl, REQUESTS_PER_SET)
cpu_utilization_data = {
    "With Rate Limiting": cpu_utilization_with_rl,
    "Without Rate Limiting": cpu_utilization_without_rl
}

# Bar chart for Total CPU utilization
st.bar_chart(cpu_utilization_data)

# Response Time Bar Graph (Average Response Time)
st.subheader("Average Response Time Per Set of Requests")
response_time_with_rl = aggregate_metrics(st.session_state.response_time_with_rl, REQUESTS_PER_SET)
response_time_without_rl = aggregate_metrics(st.session_state.response_time_without_rl, REQUESTS_PER_SET)
response_time_data = {
    "With Rate Limiting": response_time_with_rl,
    "Without Rate Limiting": response_time_without_rl
}

# Bar chart for response times
st.bar_chart(response_time_data)


  
# Save block data before app closes or after any changes  
save_block_data()  
