from flask import render_template, request, jsonify, current_app
from app import app, limiter
from app.url_scanner import URLScanner
from app.file_scanner import FileScanner
import os
import validators
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from typing import List, Dict
import concurrent.futures

url_scanner = URLScanner()
file_scanner = FileScanner()

# Configure maximum content length (50MB)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

def validate_url(url):
    if not isinstance(url, str):
        return False, "URL must be a string"
    if not url:
        return False, "URL cannot be empty"
    if not validators.url(url):
        return False, "Invalid URL format"
    return True, None

@app.route('/')
@app.route('/index')
def index():
    return "Hello, World!"

@app.route('/scan/url', methods=['POST'])
@limiter.limit("10/minute")
def scan_url():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    url = data.get('url')
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Validate URL
    is_valid, error_message = validate_url(url)
    if not is_valid:
        return jsonify({'error': error_message}), 400
    
    try:
        result = url_scanner.scan_url(url)
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error scanning URL {url}: {str(e)}")
        return jsonify({'error': 'Internal server error during URL scanning'}), 500

@app.route('/scan/url/monitor', methods=['POST'])
@limiter.limit("5/minute")
def monitor_url():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    urls = data.get('urls', [])
    if not isinstance(urls, list):
        return jsonify({'error': 'URLs must be provided as an array'}), 400
    
    results = []
    invalid_urls = []
    
    for url in urls:
        # Validate URL
        is_valid, error_message = validate_url(url)
        if not is_valid:
            invalid_urls.append({'url': url, 'error': error_message})
            continue
        
        try:
            result = url_scanner.scan_url(url)
            results.append(result)
        except Exception as e:
            app.logger.error(f"Error scanning URL {url}: {str(e)}")
            results.append({
                'url': url,
                'error': 'Internal server error during scanning'
            })
    
    return jsonify({
        'results': results,
        'total': len(urls),
        'successful_scans': len(results),
        'invalid_urls': invalid_urls,
        'malicious_count': sum(1 for r in results if isinstance(r, dict) and r.get('is_malicious', False))
    })

# File type configurations
ALLOWED_EXTENSIONS = {
    # Document formats
    'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
    # Archive formats
    'zip', 'rar',
    # Additional formats for testing/analysis
    'dat', 'bin'  # Allow binary and data files for analysis
}

RESTRICTED_EXTENSIONS = {
    'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'js'
}

def allowed_file(filename, allow_restricted=False):
    """
    Check if file extension is allowed.
    
    Args:
        filename: Name of the file to check
        allow_restricted: Whether to allow restricted file types (for analysis)
    """
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    if allow_restricted:
        return ext in ALLOWED_EXTENSIONS or ext in RESTRICTED_EXTENSIONS
    return ext in ALLOWED_EXTENSIONS

@app.route('/scan/file', methods=['POST'])
@limiter.limit("3/minute")
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({
                'error': 'File type not allowed',
                'message': f'Allowed file types are: {", ".join(ALLOWED_EXTENSIONS)}'
            }), 400

        filename = secure_filename(file.filename)
        upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
        
        try:
            file.save(upload_path)
            # Perform file scanning
            scan_results = file_scanner.scan_file(upload_path)
            return jsonify(scan_results)
        except IOError as e:
            app.logger.error(f"IO Error processing file {filename}: {str(e)}")
            return jsonify({'error': 'Error saving or processing file'}), 500
        except Exception as e:
            app.logger.error(f"Error processing file {filename}: {str(e)}")
            return jsonify({'error': 'Internal server error during file processing'}), 500
        finally:
            # Clean up temporary file
            if os.path.exists(upload_path):
                try:
                    os.remove(upload_path)
                except Exception as e:
                    app.logger.warning(f"Failed to clean up temporary file {upload_path}: {str(e)}")
    
    except RequestEntityTooLarge:
        return jsonify({
            'error': 'File too large',
            'message': f'File size exceeds maximum allowed size of {app.config["MAX_CONTENT_LENGTH"] / (1024*1024)}MB'
        }), 413

def process_uploaded_file(file, scanner: FileScanner) -> Dict:
    """Process a single uploaded file."""
    filename = secure_filename(file.filename)
    upload_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
    
    try:
        file.save(upload_path)
        scan_results = scanner.scan_file(upload_path)
        return scan_results
    except Exception as e:
        app.logger.error(f"Error processing file {filename}: {str(e)}")
        return {
            'file_name': filename,
            'error': str(e),
            'status': 'error'
        }
    finally:
        if os.path.exists(upload_path):
            try:
                os.remove(upload_path)
            except Exception as e:
                app.logger.warning(f"Failed to clean up temporary file {upload_path}: {str(e)}")

@app.route('/scan/files', methods=['POST'])
@limiter.limit("2/minute")
def scan_multiple_files():
    """Endpoint for scanning multiple files in parallel."""
    if 'files[]' not in request.files:
        return jsonify({'error': 'No files provided'}), 400
    
    files = request.files.getlist('files[]')
    if not files:
        return jsonify({'error': 'No files selected'}), 400
    
    # Sort files into allowed and restricted categories
    allowed_files = []
    restricted_files = []
    invalid_files = []
    
    for file in files:
        if file.filename == '':
            continue
            
        ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else None
        if ext in ALLOWED_EXTENSIONS:
            allowed_files.append(file)
        elif ext in RESTRICTED_EXTENSIONS:
            restricted_files.append(file)
        else:
            invalid_files.append(file.filename)
    
    if invalid_files:
        return jsonify({
            'error': 'Invalid file types detected',
            'message': f'Files with unsupported extensions: {", ".join(invalid_files)}. Allowed types are: {", ".join(sorted(ALLOWED_EXTENSIONS))}',
            'restricted_files': [f.filename for f in restricted_files]
        }), 400
    
    scanner = FileScanner()
    results = []
    
    # Process files in parallel using a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        # Process regular files
        future_to_file = {
            executor.submit(process_uploaded_file, file, scanner): file.filename
            for file in allowed_files
        }
        
        # Process restricted files with warning
        if restricted_files:
            for file in restricted_files:
                results.append({
                    'file_name': file.filename,
                    'status': 'warning',
                    'message': 'File type requires special handling and may be dangerous',
                    'is_restricted': True
                })
        
        # Collect results from parallel processing
        for future in concurrent.futures.as_completed(future_to_file):
            filename = future_to_file[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    'file_name': filename,
                    'error': str(e),
                    'status': 'error'
                })
    
    # Calculate summary statistics
    summary = {
        'total_files': len(results),
        'clean_files': sum(1 for r in results if not r.get('is_malicious', False) and 'error' not in r and not r.get('is_restricted', False)),
        'malicious_files': sum(1 for r in results if r.get('is_malicious', False)),
        'restricted_files': sum(1 for r in results if r.get('is_restricted', False)),
        'errors': sum(1 for r in results if 'error' in r),
        'threat_levels': {
            'critical': sum(1 for r in results if r.get('threat_level') == 'critical'),
            'high': sum(1 for r in results if r.get('threat_level') == 'high'),
            'medium': sum(1 for r in results if r.get('threat_level') == 'medium'),
            'low': sum(1 for r in results if r.get('threat_level') == 'low'),
            'clean': sum(1 for r in results if r.get('threat_level') == 'clean')
        }
    }
    
    return jsonify({
        'results': results,
        'summary': summary
    })

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded', 'message': str(e.description)}), 429

@app.errorhandler(413)
def too_large(e):
    return jsonify({
        'error': 'File too large',
        'message': f'File size exceeds maximum allowed size of {app.config["MAX_CONTENT_LENGTH"] / (1024*1024)}MB'
    }), 413

@app.errorhandler(500)
def internal_error(e):
    return jsonify({
        'error': 'Internal server error',
        'message': str(e)
    }), 500