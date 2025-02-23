Date: 10-2-2025
Tools used: Nmap, Openvas,etc
Nmap Scan Report - Shelby & kali
Date: 05-2-2025
Target Information:
Target IP Address: 
- 172.20.10.5
- 192.168.25.136
Hostname: shelby & kali
Scan type used:
nmap -sV -A -p- [Target IP Address]
( -sV: Service Version Detection, -A: OS and Aggressive Scanning. -p-: Scans all ports)
Explanation: This command scans all ports.detects running services,and enables aggressive scanning for OS detection
### Findings: 
open ports: 22(SSH-TCP)
Operating System:  Windows XP (outdated, with critical vulnerabilities)
Potential vulnerabilities:
port 22 (TCP) is open, which could be vulnerable to TCP-related exploits like TCP Session Hijacking,SYN Flooding 
- TCP Session Hijacking: Attackers can intercept SSH sessions if encryption is weak.
- SYN Flooding: Attackers can send excessive SYN packets, causing DOS attacks.
Risk level: Medium to High, depending on SSH version and Configuration
Recommendation:
- Use key=based authentication instead of password-based authentication.
- Disable root login ('PermitRootLogin no') in '/etc/ssh/sshd_config'.
- change the default SSH port (e.g., from 22 to 2222) to prevent automated scans.
- install fail2ban to block repeated failed login attempts.
- keep SSH updated to patch known vulnerabilities.
