import argparse
import sys
import os
from datetime import datetime

# Import local modules
try:
    from banner import print_banner
    from parser import LogParser
    from analyzer import LogAnalyzer
    from threat_model import ThreatModel
    from ai_summary import AISummaryGenerator
except ImportError as e:
    print(f"Critical Error: Missing project files. {e}")
    sys.exit(1)

# Import third-party libraries with safe fallbacks/warnings
try:
    from colorama import init, Fore, Style
    from tabulate import tabulate
    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
    # Define dummy fallbacks for colorama to prevent crashes if missing
    class DummyColor:
        def __getattr__(self, name): return ""
    Fore = DummyColor()
    Style = DummyColor()
    def init(*args, **kwargs): pass
    def tabulate(data, headers, **kwargs):
        # Basic fallback for table printing
        lines = [str(headers)]
        for row in data:
            lines.append(str(row))
        return "\n".join(lines)

def main():
    # Initialize colorama
    init()
    print_banner()

    if not HAS_LIBS:
        print(f"{Fore.YELLOW}Warning: 'colorama' and 'tabulate' libraries not found.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Output formatting will be degraded. Run 'pip install -r requirements.txt'{Style.RESET_ALL}\n")

    # CLI Argument Parsing
    parser_arg = argparse.ArgumentParser(description="VSMK-AegisLog: AI-Powered Log Analyzer")
    parser_arg.add_argument("--log", help="Path to the log file to analyze", default=None)
    parser_arg.add_argument("--type", help="Log type (ssh or apache)", choices=['ssh', 'apache'], default='ssh')
    args = parser_arg.parse_args()

    # Determine file path
    log_path = args.log
    if not log_path:
        # Default to sample SSH log
        base_dir = os.path.dirname(os.path.abspath(__file__))
        default_log = os.path.join(base_dir, "data", "sample_logs", "ssh.log")
        
        if not args.log:
            print(f"{Fore.CYAN}[INFO] No log file specified. Using default sample log.{Style.RESET_ALL}")
            log_path = default_log

    # Validate file existence
    if not os.path.exists(log_path):
        print(f"{Fore.RED}[ERROR] File not found: {log_path}{Style.RESET_ALL}")
        print(f"Available samples:")
        print(f"  - data/sample_logs/ssh.log")
        print(f"  - data/sample_logs/apache.log")
        sys.exit(1)

    print(f"{Fore.GREEN}[+] Starting analysis on: {log_path} ({args.type}){Style.RESET_ALL}")

    # Pipeline Initialization
    log_parser = LogParser()
    analyzer = LogAnalyzer()
    threat_model = ThreatModel()
    ai_gen = AISummaryGenerator()

    # Processing
    record_count = 0
    print(f"{Fore.CYAN}[*] Parsing logs...{Style.RESET_ALL}")
    
    try:
        for record in log_parser.parse_file(log_path, args.type):
            analyzer.process_record(record)
            record_count += 1
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Processing failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

    if record_count == 0:
        print(f"{Fore.YELLOW}[!] No valid records found in log file.{Style.RESET_ALL}")
        sys.exit(0)

    print(f"{Fore.GREEN}[+] Parsed {record_count} events.{Style.RESET_ALL}")

    # Analysis & Scoring
    features = analyzer.get_features()
    suspicious_ips = analyzer.get_suspicious_ips()
    score = threat_model.predict_score(features)
    level = threat_model.get_threat_level(score)

    # Output Generation
    print("\n" + "="*60)
    print(f"{Fore.YELLOW}ANALYSIS RESULTS{Style.RESET_ALL}")
    print("="*60)

    # Statistics Table
    stats_data = [
        ["Total Events", analyzer.stats['total_events']],
        ["Failed Logins", analyzer.stats['failed_logins']],
        ["Successful Logins", analyzer.stats['successful_logins']],
        ["Unique IPs", len(analyzer.stats['unique_ips'])]
    ]
    print(tabulate(stats_data, headers=["Metric", "Value"], tablefmt="fancy_grid"))

    # Suspicious IPs Table
    if suspicious_ips:
        print(f"\n{Fore.RED}TOP SUSPICIOUS SOURCES:{Style.RESET_ALL}")
        sus_data = suspicious_ips[:5] # Top 5
        print(tabulate(sus_data, headers=["IP Address", "Failed Attempts"], tablefmt="fancy_grid"))
    else:
        print(f"\n{Fore.GREEN}No suspicious IPs detected.{Style.RESET_ALL}")

    # Threat Score Display
    color = Fore.GREEN
    if level == "MEDIUM": color = Fore.YELLOW
    if level == "HIGH": color = Fore.RED
    
    print("\n" + "-"*60)
    print(f"THREAT SCORE: {color}{score}/100{Style.RESET_ALL}  [{level}]")
    print("-"*60)

    # AI Summary
    print(f"\n{Fore.CYAN}AI SECURITY SUMMARY:{Style.RESET_ALL}")
    summary = ai_gen.generate_summary(analyzer.stats, suspicious_ips, score, level)
    print(summary)
    print("\n" + "="*60)
    print(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()
