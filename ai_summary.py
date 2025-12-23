import random

class AISummaryGenerator:
    """
    Generates an AI-style human-readable summary of the security analysis.
    """
    
    def generate_summary(self, stats, suspicious_ips, threat_score, threat_level):
        """
        Constructs a narrative summary based on analysis results.
        """
        lines = []
        
        # Intro
        lines.append(f"Analysis complete. The calculated Threat Score is {threat_score}/100 ({threat_level}).")
        
        # Contextual analysis
        if threat_level == "HIGH":
            lines.append(f"CRITICAL ALERT: The system is exhibiting signs of an active attack.")
            lines.append(f"Multiple failed authentication attempts ({stats['failed_logins']}) were detected.")
        elif threat_level == "MEDIUM":
            lines.append(f"WARNING: Suspicious activity detected. Monitoring is recommended.")
            lines.append(f"There is an elevated rate of failed logins relative to successful ones.")
        else:
            lines.append(f"System status appears normal. Occasional failed logins are expected.")

        # IP Specifics
        if suspicious_ips:
            top_ip, count = suspicious_ips[0]
            lines.append(f"The primary source of suspicious activity is {top_ip} with {count} failed attempts.")
            if len(suspicious_ips) > 1:
                lines.append(f"Other contributing sources include {suspicious_ips[1][0]}.")
        
        # Recommendations
        lines.append("\nRECOMMENDATIONS:")
        if threat_level == "HIGH":
            lines.append("- IMMEDIATELY block the identified IPs using iptables or ufw.")
            lines.append(f"  Example: sudo ufw deny from {suspicious_ips[0][0]}")
            lines.append("- Review /var/log/auth.log for successful entries from these IPs.")
            lines.append("- Consider implementing Fail2Ban to automate blocking.")
        elif threat_level == "MEDIUM":
            lines.append("- Monitor the top suspicious IPs for further activity.")
            lines.append("- Verify if these are legitimate users (e.g., forgotten passwords).")
        else:
            lines.append("- Routine log rotation and monitoring is sufficient.")
            
        return "\n".join(lines)