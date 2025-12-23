import re
from datetime import datetime

class LogParser:
    """
    Parses SSH and Apache logs into structured dictionaries.
    """
    
    # Regex patterns
    SSH_PATTERN = re.compile(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[\d+\]:\s+(.*)$')
    APACHE_PATTERN = re.compile(r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d{3}) (\d+|-)')
    
    def __init__(self):
        pass

    def parse_file(self, file_path, log_type='ssh'):
        """
        Generator that reads a file and yields parsed records.
        """
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parsed = self.parse_line(line, log_type)
                    if parsed:
                        yield parsed
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}")
        except Exception as e:
            print(f"Error reading file: {e}")

    def parse_line(self, line, log_type):
        if log_type == 'ssh':
            return self._parse_ssh(line)
        elif log_type == 'apache':
            return self._parse_apache(line)
        else:
            return None

    def _parse_ssh(self, line):
        match = self.SSH_PATTERN.match(line)
        if not match:
            return None
        
        timestamp_str, host, message = match.groups()
        
        # Extract IP if present in message
        ip_match = re.search(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        ip = ip_match.group(1) if ip_match else None
        
        # Determine event type
        event_type = 'info'
        if 'Failed password' in message:
            event_type = 'failed_login'
        elif 'Accepted' in message:
            event_type = 'successful_login'
        elif 'Invalid user' in message:
            event_type = 'invalid_user'
            
        return {
            'timestamp': timestamp_str,
            'source_ip': ip,
            'event_type': event_type,
            'message': message,
            'log_type': 'ssh',
            'raw': line
        }

    def _parse_apache(self, line):
        match = self.APACHE_PATTERN.match(line)
        if not match:
            return None
            
        ip, timestamp_str, request, status, size = match.groups()
        
        # Basic event classification
        event_type = 'access'
        status = int(status)
        if status == 401 or status == 403:
            event_type = 'auth_fail'
        elif status == 404:
            event_type = 'not_found'
        elif status >= 500:
            event_type = 'server_error'
            
        return {
            'timestamp': timestamp_str,
            'source_ip': ip,
            'event_type': event_type,
            'message': f"{request} (Status: {status})",
            'log_type': 'apache',
            'status': status,
            'raw': line
        }
