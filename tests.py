import requests
import time

BASE_URL = "http://localhost:5000"

def test_single_url():
    print("\nTesting single URL scanning...")
    urls = [
        "https://www.google.com",  # legitimate
        "http://malware.wicar.org/data/js_crypto_miner.html",  # malicious
        "not_a_url",  # invalid
    ]
    
    for url in urls:
        response = requests.post(f"{BASE_URL}/scan/url", json={"url": url})
        print(f"\nURL: {url}")
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")

def test_bulk_urls():
    print("\nTesting bulk URL monitoring...")
    urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "http://malware.wicar.org/data/js_crypto_miner.html",
        "invalid_url"
    ]
    
    response = requests.post(f"{BASE_URL}/scan/url/monitor", json={"urls": urls})
    print(f"\nStatus: {response.status_code}")
    print(f"Response: {response.json()}")

def test_rate_limiting():
    print("\nTesting rate limiting...")
    url = "https://www.google.com"
    
    for i in range(12):  # Should hit rate limit after 10 requests
        response = requests.post(f"{BASE_URL}/scan/url", json={"url": url})
        print(f"Request {i+1}: Status {response.status_code}")
        if response.status_code != 200:
            print(f"Error: {response.json()}")
        time.sleep(0.5)  # Small delay between requests

if __name__ == "__main__":
    print("Starting API tests...")
    test_single_url()
    test_bulk_urls()
    test_rate_limiting()