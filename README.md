# Security Log Consolidator

A local web application for parsing, filtering, and exporting security scan logs.

![Screenshot](screenshot.png)

## Features

- **Parse Logs**: Upload or paste security scan logs in the expected format
- **Filter by Triage Level**: Filter entries by Red, Yellow, Green, or other triage levels
- **Export to CSV**: Export filtered results with all columns:
  - Timestamp
  - Log Entry Type  
  - Triage Level
  - Matched Rule Name
  - R/RW (Read/Write permissions)
  - File Size
  - File Last Modified
  - Full File Path
  - Match Context
- **Statistics Dashboard**: See counts by triage level at a glance

## Expected Log Format

```
TIMESTAMP [LogEntryType] {TriageLevel}<RuleName|R/RW|REGEX> FILESIZE|LASTMODIFIED>(FILEPATH) MATCHCONTENT
```

Example:
```
2020-05-30 19:37:18 +08:00 [File] {Red}<KeepConfigRegexRed|R|validationkey[[:space:]]*=...> 208kB|10/01/2020 3:44:02 PM>(\\WEB01.asterlab.localdomain\wss\VirtualDirectories\80\web.config) <machineKey validationKey="74CA63C3590C987B65...
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip

### Setup

1. Clone or download this repository

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to:
```
http://localhost:5000
```

3. Either:
   - Drag and drop a log file onto the upload zone
   - Click "browse files" to select a file
   - Paste log content directly into the text area

4. Click **Parse Logs** to process the data

5. Use the triage level filters on the right to filter entries

6. Click **Download CSV** to export the filtered results

## Project Structure

```
log-consolidator/
├── app.py              # Flask application
├── requirements.txt    # Python dependencies
├── README.md          # This file
└── templates/
    └── index.html     # Web interface
```

## CSV Export Columns

| Column | Description |
|--------|-------------|
| Timestamp | When the log entry was recorded |
| Log Entry Type | Type of entry (File, Share, etc.) |
| Triage Level | Severity level (Red, Yellow, Green, etc.) |
| Matched Rule Name | Name of the security rule that matched |
| R/RW | Read/Write permission indicator |
| File Size | Size of the scanned file |
| File Last Modified | When the file was last modified |
| Full File Path | Complete path to the file |
| Match Context | The actual content that matched the rule |

## Customization

### Adding New Triage Levels

The application automatically detects triage levels from the parsed logs. Any level found in `{Level}` format will be displayed.

### Modifying the Regex Parser

If your log format differs slightly, modify the `parse_log_line()` function in `app.py`. The current pattern expects:

```python
pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[+-]\d{2}:\d{2})\s+\[(\w+)\]\s+\{(\w+)\}<([^|]+)\|([^|]+)\|([^>]+)>\s+([^|]+)\|([^>]+)>\(([^)]+)\)\s*(.*)$'
```

## Security Note

This application runs locally and never sends your log data to any external server. All processing happens in your browser and on your local machine.

## License

MIT License
