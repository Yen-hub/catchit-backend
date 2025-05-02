# CatchIt! - Advanced File and URL Scanner

CatchIt! is a sophisticated security scanning service that provides real-time analysis of files and URLs for potential security threats. It combines multiple scanning techniques, including machine learning-based URL analysis, binary file analysis, and pattern matching to detect malicious content.

## Features

### File Scanning

- **Multiple File Types Support**: Analyzes various file formats including documents (txt, pdf, doc, docx, xls, xlsx) and archives (zip, rar)
- **Binary Analysis**: Deep inspection of executable files for:
  - Suspicious API calls
  - Code injection patterns
  - Entropy analysis
  - PE file structure analysis
- **Archive Scanning**: Detection of:
  - Zip bombs
  - Suspicious nested archives
  - Hidden malicious files
- **Content Analysis**:
  - Pattern matching for malicious code
  - Obfuscation detection
  - File type verification
  - Entropy analysis

### URL Scanning

- **Machine Learning-Based Analysis**: Uses transformer models to classify URLs into:
  - Benign
  - Defacement
  - Phishing
  - Malware
- **Batch URL Processing**: Ability to scan multiple URLs simultaneously
- **Real-time Monitoring**: Support for continuous URL monitoring

### Security Features

- **Rate Limiting**: Prevents abuse through configurable rate limits
- **File Size Restrictions**: Maximum file size limit of 50MB
- **Type Verification**: Ensures file extensions match their content
- **Safe Handling**: Secure processing of potentially dangerous files

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Virtual environment (recommended)

### Installation

1. Clone the repository:

```bash
[git clone https://github.com/yourusername/catchit.git](https://github.com/Yen-hub/catchit-backend)
cd catchit-backend
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Unix or MacOS:
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Initialize the application:

```bash
python run.py
```

The server will start at `http://localhost:5000`

## API Documentation

### File Scanning Endpoints

#### Single File Scan

```http
POST /scan/file
Content-Type: multipart/form-data

file: <file>
```

**Rate Limit**: 3 requests per minute

**Response**:

```json
{
  "file_name": "example.txt",
  "file_size": 1234,
  "hashes": {
    "md5": "...",
    "sha1": "...",
    "sha256": "..."
  },
  "is_malicious": false,
  "scan_results": [
    {
      "check": "signature_check",
      "status": "clean",
      "severity": "clean",
      "message": "No threats detected"
    }
    // ... other check results
  ],
  "threat_level": "clean"
}
```

#### Batch File Scan

```http
POST /scan/files
Content-Type: multipart/form-data

files[]: <file1>
files[]: <file2>
...
```

**Rate Limit**: 2 requests per minute

**Response**:

```json
{
    "results": [...],
    "summary": {
        "total_files": 5,
        "clean_files": 3,
        "malicious_files": 1,
        "restricted_files": 1,
        "errors": 0,
        "threat_levels": {
            "critical": 0,
            "high": 1,
            "medium": 0,
            "low": 0,
            "clean": 3
        }
    }
}
```

### URL Scanning Endpoints

#### Single URL Scan

```http
POST /scan/url
Content-Type: application/json

{
    "url": "https://example.com"
}
```

**Rate Limit**: 10 requests per minute

**Response**:

```json
{
  "url": "https://example.com",
  "classification": "Benign",
  "is_malicious": false,
  "confidence": 0.98
}
```

#### Bulk URL Monitor

```http
POST /scan/url/monitor
Content-Type: application/json

{
    "urls": [
        "https://example1.com",
        "https://example2.com"
    ]
}
```

**Rate Limit**: 5 requests per minute

**Response**:

```json
{
    "results": [...],
    "total": 2,
    "successful_scans": 2,
    "invalid_urls": [],
    "malicious_count": 0
}
```

## Error Handling

The API uses standard HTTP status codes:

- `200`: Success
- `400`: Bad Request (invalid input)
- `413`: Payload Too Large (file size exceeds limit)
- `429`: Too Many Requests (rate limit exceeded)
- `500`: Internal Server Error

Error responses include descriptive messages:

```json
{
  "error": "Rate limit exceeded",
  "message": "3 per 1 minute"
}
```

## Security Dataset

The system uses a comprehensive security dataset containing:

- Known malware signatures
- Suspicious code patterns
- File characteristics
- Binary analysis patterns

The dataset is automatically initialized and can be updated through the MalwareDataset class.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Uses the HuggingFace Transformers library for URL classification
- Implements industry-standard security scanning techniques
- Follows OWASP security guidelines for file handling
