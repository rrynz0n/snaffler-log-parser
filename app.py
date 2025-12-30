#!/usr/bin/env python3
"""
Snaffler Log Consolidator - Web Application
Parses Snaffler security scan logs and exports to CSV with filtering.
Optimized for large files (100MB+).
"""

from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import re
import csv
import io
import os
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional, Generator
import tempfile
import json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max upload

# Temp storage for parsed data
TEMP_DIR = tempfile.mkdtemp()
PARSED_FILE = os.path.join(TEMP_DIR, 'parsed_entries.jsonl')
UPLOAD_FILE = os.path.join(TEMP_DIR, 'input.log')

@dataclass
class LogEntry:
    timestamp: str
    log_entry_type: str
    triage_level: str
    matched_rule_name: str
    read_write: str
    matched_regex: str
    file_size: str
    file_last_modified: str
    server: str
    full_file_path: str
    match_context: str

def extract_server(path: str) -> str:
    """Extract server name from UNC path like \\\\SERVER\\share\\path"""
    if path.startswith('\\\\'):
        # Remove leading backslashes and split
        parts = path[2:].split('\\')
        if parts:
            return parts[0]
    return ''

# Compile regex patterns for Snaffler log format
# Format 1 - File entries: [HOST] TIMESTAMP [File] {Level}<RuleName|R/RW|Pattern|Size|DateTime>(Path) Context
# Format 2 - Share entries: [HOST] TIMESTAMP [Share] {Level}<\\Path>(R/RW) Description

# File entry pattern - use >( to find end of metadata since regex pattern may contain >
FILE_PATTERN = re.compile(
    r'^\[[^\]]+\]\s+'                              # [HOST] - ignore
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z?)\s+'   # Timestamp (group 1)
    r'\[(\w+)\]\s+'                                 # [File] (group 2)
    r'\{(\w+)\}'                                    # {TriageLevel} (group 3)
    r'<(.+)>\('                                     # <...metadata...>( - greedy match until >( (group 4)
    r'([^)]+)\)\s*'                                 # (FilePath) (group 5)
    r'(.*)$',                                       # Context (group 6)
    re.DOTALL
)

# Share entry pattern - simpler format
SHARE_PATTERN = re.compile(
    r'^\[[^\]]+\]\s+'                              # [HOST] - ignore
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}Z?)\s+'   # Timestamp
    r'\[(\w+)\]\s+'                                 # [Share]
    r'\{(\w+)\}'                                    # {TriageLevel}
    r'<([^>]+)>'                                    # <\\SharePath>
    r'\(([^)]+)\)\s*'                               # (R/RW)
    r'(.*)$',                                       # Description
    re.DOTALL
)

def parse_file_metadata(metadata: str) -> tuple:
    """Parse the pipe-separated metadata from File entries.
    Format: RuleName|R/RW|Pattern|Size|DateTime
    The Pattern field may contain | characters, so we parse from both ends.
    """
    parts = metadata.split('|')
    if len(parts) >= 5:
        rule_name = parts[0]
        read_write = parts[1]
        # Size and DateTime are the last two parts
        file_datetime = parts[-1]
        file_size = parts[-2]
        # Everything in between is the pattern (may contain |)
        pattern = '|'.join(parts[2:-2])
        return rule_name, read_write, pattern, file_size, file_datetime
    elif len(parts) >= 2:
        return parts[0], parts[1], '', '', ''
    else:
        return metadata, '', '', '', ''

def parse_log_line(line: str) -> Optional[LogEntry]:
    """Parse a single Snaffler log line into a LogEntry object."""
    line = line.strip()
    if not line:
        return None
    
    # Skip info/status lines (these are multi-line status updates)
    if '[Info]' in line:
        return None
    
    # Skip status update continuation lines
    skip_patterns = [
        'ShareFinder Tasks',
        'TreeWalker Tasks',
        'FileScanner Tasks',
        'RAM in use',
        'Insufficient',
        'Max ShareFinder',
        'Max TreeWalker', 
        'Max FileScanner',
        'Been Snafflin',
        'Status Update'
    ]
    for pattern in skip_patterns:
        if pattern in line:
            return None
    
    # Check entry type and use appropriate pattern
    if '[Share]' in line:
        # Use Share pattern for Share entries
        match = SHARE_PATTERN.match(line)
        if match:
            file_path = match.group(4)
            return LogEntry(
                timestamp=match.group(1),
                log_entry_type=match.group(2),
                triage_level=match.group(3),
                matched_rule_name='',                 # No rule name for shares
                read_write=match.group(5),            # R or RW from parentheses
                matched_regex='',                      # No regex for shares
                file_size='',                          # No size for shares
                file_last_modified='',                 # No mod time for shares
                server=extract_server(file_path),     # Extract server from path
                full_file_path=file_path,             # The share path from <\\PATH>
                match_context=match.group(6).strip() if match.group(6) else ''  # Description
            )
    
    elif '[File]' in line:
        # Use File pattern for File entries
        match = FILE_PATTERN.match(line)
        if match:
            # Parse the metadata field
            metadata = match.group(4)
            rule_name, read_write, pattern, file_size, file_datetime = parse_file_metadata(metadata)
            file_path = match.group(5)
            
            return LogEntry(
                timestamp=match.group(1),
                log_entry_type=match.group(2),
                triage_level=match.group(3),
                matched_rule_name=rule_name,
                read_write=read_write,
                matched_regex=pattern,
                file_size=file_size,
                file_last_modified=file_datetime,
                server=extract_server(file_path),
                full_file_path=file_path,
                match_context=match.group(6).strip() if match.group(6) else ''
            )
    
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload separately from parsing."""
    if 'log_file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['log_file']
    if not file.filename:
        return jsonify({'error': 'No file selected'}), 400
    
    # Save uploaded file
    file.save(UPLOAD_FILE)
    
    file_size = os.path.getsize(UPLOAD_FILE)
    print(f"File uploaded: {file.filename}, size: {file_size / 1024 / 1024:.2f} MB")
    
    return jsonify({
        'success': True,
        'filename': file.filename,
        'size': file_size
    })

@app.route('/parse-uploaded', methods=['POST'])
def parse_uploaded_file():
    """Parse the previously uploaded file with SSE progress."""
    
    if not os.path.exists(UPLOAD_FILE):
        return jsonify({'error': 'No file uploaded. Please upload a file first.'}), 400
    
    def generate():
        triage_counts = {}
        total_entries = 0
        last_progress = -1
        lines_processed = 0
        
        file_size = os.path.getsize(UPLOAD_FILE)
        bytes_read = 0
        
        print(f"Starting parse of {file_size / 1024 / 1024:.2f} MB file")
        
        try:
            with open(PARSED_FILE, 'w', encoding='utf-8') as out:
                with open(UPLOAD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        lines_processed += 1
                        bytes_read += len(line.encode('utf-8', errors='ignore'))
                        
                        entry = parse_log_line(line)
                        if entry:
                            out.write(json.dumps(asdict(entry)) + '\n')
                            total_entries += 1
                            triage_counts[entry.triage_level] = triage_counts.get(entry.triage_level, 0) + 1
                        
                        # Send progress every 1%
                        progress = int((bytes_read / file_size) * 100)
                        if progress > last_progress:
                            last_progress = progress
                            yield f"data: {json.dumps({'progress': progress, 'entries': total_entries, 'lines': lines_processed})}\n\n"
            
            # Clean up input file
            try:
                os.remove(UPLOAD_FILE)
            except:
                pass
            
            print(f"Parse complete: {total_entries} entries found from {lines_processed} lines")
            
            # Final result
            yield f"data: {json.dumps({'done': True, 'total_entries': total_entries, 'triage_levels': sorted(triage_counts.keys()), 'triage_counts': triage_counts})}\n\n"
            
        except Exception as e:
            print(f"Parse error: {e}")
            import traceback
            traceback.print_exc()
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/entries')
def get_entries():
    """Get paginated entries with optional filtering."""
    
    if not os.path.exists(PARSED_FILE):
        return jsonify({'error': 'No data loaded. Please parse a log file first.'}), 400
    
    # Pagination params
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 100))
    
    # Filter params
    triage_filter = request.args.getlist('triage')
    
    entries = []
    total_filtered = 0
    skip = (page - 1) * per_page
    
    with open(PARSED_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            entry = json.loads(line)
            
            # Apply triage filter
            if triage_filter and entry['triage_level'] not in triage_filter:
                continue
            
            total_filtered += 1
            
            # Pagination
            if total_filtered > skip and len(entries) < per_page:
                # Truncate match_context for display
                if len(entry['match_context']) > 200:
                    entry['match_context'] = entry['match_context'][:200] + '...'
                entries.append(entry)
    
    return jsonify({
        'entries': entries,
        'page': page,
        'per_page': per_page,
        'total': total_filtered,
        'total_pages': (total_filtered + per_page - 1) // per_page if total_filtered > 0 else 1
    })

@app.route('/export', methods=['POST'])
def export_csv():
    """Export filtered entries to CSV with streaming."""
    
    if not os.path.exists(PARSED_FILE):
        return jsonify({'error': 'No data loaded'}), 400
    
    data = request.get_json() or {}
    triage_filter = data.get('triage_levels', [])
    
    def generate():
        # Header
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'Timestamp',
            'Log Entry Type',
            'Triage Level',
            'Matched Rule Name',
            'R/RW',
            'File Size',
            'File Last Modified',
            'Server',
            'Full File Path',
            'Match Context'
        ])
        yield output.getvalue()
        
        # Data rows
        with open(PARSED_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                entry = json.loads(line)
                
                # Apply filter
                if triage_filter and entry['triage_level'] not in triage_filter:
                    continue
                
                output = io.StringIO()
                writer = csv.writer(output)
                writer.writerow([
                    entry['timestamp'],
                    entry['log_entry_type'],
                    entry['triage_level'],
                    entry['matched_rule_name'],
                    entry['read_write'],
                    entry['file_size'],
                    entry['file_last_modified'],
                    entry['server'],
                    entry['full_file_path'],
                    entry['match_context']
                ])
                yield output.getvalue()
    
    filename = f"snaffler_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/debug-sample', methods=['POST'])
def debug_sample():
    """Debug endpoint - show first 50 lines and parse results."""
    
    if not os.path.exists(UPLOAD_FILE):
        return jsonify({'error': 'No file uploaded'}), 400
    
    results = []
    with open(UPLOAD_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            if i >= 50:
                break
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            entry = parse_log_line(line_stripped)
            results.append({
                'line_num': i + 1,
                'raw': line_stripped[:300] + '...' if len(line_stripped) > 300 else line_stripped,
                'parsed': asdict(entry) if entry else None,
                'matched': entry is not None
            })
    
    matched = sum(1 for r in results if r['matched'])
    return jsonify({
        'total_lines': len(results),
        'matched': matched,
        'results': results
    })

@app.route('/clear', methods=['POST'])
def clear_data():
    """Clear parsed data."""
    try:
        if os.path.exists(PARSED_FILE):
            os.remove(PARSED_FILE)
        if os.path.exists(UPLOAD_FILE):
            os.remove(UPLOAD_FILE)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print(f"Temp directory: {TEMP_DIR}")
    print("Starting Snaffler Log Consolidator...")
    print("Open http://localhost:5000 in your browser")
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)