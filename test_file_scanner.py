import os
import requests
import tempfile
import zipfile
import base64
import struct
import time
from pathlib import Path

BASE_URL = "http://localhost:5000"

def create_test_files():
    """Create test files with various characteristics."""
    test_files = {}
    
    # Normal text file
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b"This is a normal text file with regular content.")
        test_files['normal_text'] = f.name
    
    # File with suspicious patterns
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b"powershell -enc ZQBjAGgAbwAgACIASABlAGwAbABvACIA\n")
        f.write(b"cmd.exe /c echo hello\n")
        f.write(b"<script>document.write('test')</script>")
        test_files['suspicious_patterns'] = f.name
    
    # Text file with wrong extension
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
        f.write(b"This is actually a text file with .pdf extension")
        test_files['mismatched_type'] = f.name
    
    # Create a suspicious ZIP file
    zip_path = tempfile.mktemp(suffix='.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Add a normal file
        zf.writestr("normal.txt", "This is a normal file")
        # Add a suspicious file
        zf.writestr("suspicious.vbs", "CreateObject(\"WScript.Shell\").Run \"cmd.exe\"")
        # Add a hidden file
        zf.writestr(".__hidden", "Hidden file content")
    test_files['suspicious_archive'] = zip_path
    
    # Create a file with high entropy (encrypted-like content)
    with tempfile.NamedTemporaryFile(suffix='.dat', delete=False) as f:
        f.write(os.urandom(1024 * 1024))  # 1MB of random data
        test_files['high_entropy'] = f.name
    
    # Create a text file with obfuscated content
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b"eval(base64_decode('ZWNobyAiaGVsbG8i'))\n")
        f.write(b"String.fromCharCode(72,101,108,108,111)")
        test_files['obfuscated_content'] = f.name
    
    return test_files

def test_single_file_scan():
    """Test individual file scanning endpoint."""
    print("\nTesting single file scanning...")
    test_files = create_test_files()
    
    for file_type, file_path in test_files.items():
        print(f"\nTesting {file_type}:")
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(f"{BASE_URL}/scan/file", files=files)
            
            print(f"Status: {response.status_code}")
            print(f"Response: {response.json()}")
        except Exception as e:
            print(f"Error testing {file_type}: {str(e)}")

def test_batch_file_scan():
    """Test batch file scanning endpoint."""
    print("\nTesting batch file scanning...")
    test_files = create_test_files()
    
    try:
        files = []
        for file_type, file_path in test_files.items():
            with open(file_path, 'rb') as f:
                files.append(
                    ('files[]', (os.path.basename(file_path), f.read()))
                )
        
        response = requests.post(f"{BASE_URL}/scan/files", files=files)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error testing batch scan: {str(e)}")

def test_rate_limiting():
    """Test rate limiting on file upload endpoints."""
    print("\nTesting rate limiting...")
    test_content = b"Test content for rate limit testing"
    
    print("\nTesting single file endpoint rate limit:")
    for i in range(5):  # Should hit rate limit after 3 requests
        with tempfile.NamedTemporaryFile(suffix='.txt') as tf:
            tf.write(test_content)
            tf.seek(0)
            files = {'file': ('test.txt', tf)}
            response = requests.post(f"{BASE_URL}/scan/file", files=files)
            print(f"Request {i+1}: Status {response.status_code}")
            if response.status_code != 200:
                print(f"Error: {response.json()}")
        time.sleep(0.5)  # Small delay between requests
    
    print("\nTesting batch file endpoint rate limit:")
    for i in range(4):  # Should hit rate limit after 2 requests
        with tempfile.NamedTemporaryFile(suffix='.txt') as tf:
            tf.write(test_content)
            tf.seek(0)
            files = [('files[]', ('test.txt', tf.read()))]
            response = requests.post(f"{BASE_URL}/scan/files", files=files)
            print(f"Request {i+1}: Status {response.status_code}")
            if response.status_code != 200:
                print(f"Error: {response.json()}")
        time.sleep(0.5)

def cleanup_test_files(test_files):
    """Clean up temporary test files."""
    for file_path in test_files.values():
        try:
            os.remove(file_path)
        except:
            pass

if __name__ == "__main__":
    print("Starting comprehensive file scanner tests...")
    test_files = create_test_files()
    
    try:
        test_single_file_scan()
        time.sleep(2)  # Wait for rate limit to reset
        test_batch_file_scan()
        time.sleep(2)  # Wait for rate limit to reset
        test_rate_limiting()
    finally:
        cleanup_test_files(test_files)