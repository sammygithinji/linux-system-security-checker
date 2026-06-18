# linux-system-security-checker
This is a Linux system security checker. 
It scans a computer and creates a report showing possible security weaknesses.

## How It Works
It should be run with admin (root) access for full results.
It saves a report file with the date and time in the name.
It checks several areas of the system and prints results both on-screen and into the report.

## What It Checks
1. Basic System Info
Collects simple details like computer name, software version, and how long it's been running.

2. Failed Login Attempts
Looks at login records to find people who tried (and failed) to log in. It highlights repeat offenders and suspicious activity.

3. Open Network Ports
Checks which "doors" into the computer are open. It flags risky ones that are often targeted by attackers.

4. Running Services
Lists programs currently active in the background.

5. Special Permission Files (SUID/SGID)
Finds files that give extra power to whoever runs them. These can be risky if not needed.

6. World-Writable Files
Finds files and folders that any user can change. This is a security risk if unintended.

## What You Get at the End
A summary report saved as a text file.

## Recommendations for fixing each issue found, such as:
Blocking repeat failed-login attempts
Closing unused ports
Turning off unnecessary services
Removing risky file permissions
Keeping the system updated and securing remote login settings



## Key Takeaway
This script acts like a basic health check for a Linux computer's security. 
It doesn't fix problems automatically — it just finds them and suggests next steps.
