# SSH Log Analyzer

A simple Python tool that analyzes SSH authentication logs to detect failed login attempts and count them by IP address.

## Features

- Reads and parses SSH log files
- Detects failed login attempts
- Extracts IP addresses from log entries
- Counts failed attempts per IP address


## Requirements

- Python 3
- No external dependencies

## Usage

Run the script with the path to a log file:

```
python analyzer.py <logfile>
```

On Windows you can use `py` instead of `python`:

```
py analyzer.py auth.log
```

## Example output

```
[!] Suspicious login activity detected:
203.0.113.42 --> 3 failed attempts [BRUTE FORCE SUSPECTED]
192.168.1.105 --> 1 failed attempts
```