from colorama import Fore, Style
import sys

def print_banner():
    banner = rf"""
{Fore.CYAN}
 __      __  _________   __  __   _  __         
 \ \    / / / _______/  |  \/  | | |/ /         
  \ \  / /  | (___      | \  / | | ' /          
   \ \/ /    \___ \     | |\/| | |  <           
    \  /     ____) |    | |  | | | . \          
     \/     /_____/     |_|  |_| |_|\_\         
                                                
           _______   _______   _____   _____    _       ____     _____ 
     /\   |  ____|  / ____|   |_   _| / ____|  | |     / __ \   / ____|
    /  \  | |__    | |  __      | |  | (___    | |    | |  | | | |  __ 
   / /\ \ |  __|   | | |_ |     | |   \___ \   | |    | |  | | | | |_ |
  / ____ \| |____  | |__| |    _| |_  ____) |  | |____| |__| | | |__| |
 /_/    \_\______|  \_____|   |_____||_____/   |______|\____/   \_____|
                                                                       
{Style.RESET_ALL}
{Fore.YELLOW}:: VSMK-AegisLog :: Advanced AI-Powered Log Analysis CLI ::{Style.RESET_ALL}
"""
    print(banner)

if __name__ == "__main__":
    print_banner()
