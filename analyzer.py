from collections import defaultdict, Counter

class LogAnalyzer:
    """
    Aggregates parsed log data to extract security features.
    """
    def __init__(self):
        self.stats = {
            'total_events': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'unique_ips': set(),
            'ip_events': defaultdict(list), # ip -> list of event types
            'ip_counts': Counter()
        }

    def process_record(self, record):
        """
        Ingest a single parsed record and update stats.
        """
        self.stats['total_events'] += 1
        
        ip = record.get('source_ip')
        if ip:
            self.stats['unique_ips'].add(ip)
            self.stats['ip_counts'][ip] += 1
            self.stats['ip_events'][ip].append(record.get('event_type'))

        evt = record.get('event_type')
        if evt in ['failed_login', 'auth_fail', 'invalid_user']:
            self.stats['failed_logins'] += 1
        elif evt in ['successful_login']:
            self.stats['successful_logins'] += 1

    def get_suspicious_ips(self, threshold=3):
        """
        Identify IPs with high failure counts.
        """
        suspicious = []
        for ip, events in self.stats['ip_events'].items():
            fail_count = sum(1 for e in events if e in ['failed_login', 'auth_fail', 'invalid_user'])
            if fail_count >= threshold:
                suspicious.append((ip, fail_count))
        
        return sorted(suspicious, key=lambda x: x[1], reverse=True)

    def get_features(self):
        """
        Extract numerical features for the threat model.
        """
        total = self.stats['total_events']
        if total == 0:
            return [0, 0, 0, 0]

        failed = self.stats['failed_logins']
        unique_ips = len(self.stats['unique_ips'])
        
        # Calculate max failures from a single IP
        max_single_ip_fails = 0
        suspicious = self.get_suspicious_ips(threshold=0)
        if suspicious:
            max_single_ip_fails = suspicious[0][1]

        # Feature vector:
        # 1. Failure Ratio (failed / total)
        # 2. Unique IP Count (normalized loosely by log size, but raw is okay for this logic)
        # 3. Max Failures from Single IP (brute force indicator)
        # 4. Global Fail Count
        
        return {
            'failure_ratio': failed / total,
            'unique_ip_count': unique_ips,
            'max_single_ip_fails': max_single_ip_fails,
            'total_fails': failed
        }
