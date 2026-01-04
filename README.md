👁️ SMILEX-EYE v20.0
Developed by: 0x0smilex
[!IMPORTANT] Smilex-Eye is a high-speed Shodan reconnaissance and deception-detection tool. It features a Dynamic Filter Engine that automatically adjusts based on your Shodan API subscription tier.

✨ CORE FEATURES
🚀 Master Filter Library: Instant access to 67+ specialized Shodan filters (Web, SSL, Cloud, ICS, and more).

📊 Dynamic Tier-Awareness: Intelligent logic that automatically hides filters your API plan doesn't support.

🎯 Honeypot Logic: Advanced detection of deceptive systems using official Shodan tags and banner heuristics.

💾 Clean Exporting: Save filtered IP lists directly to .txt for seamless integration with Nmap or Masscan.

📥 QUICK SETUP & INSTALLATION
To get started, clone the repository and set up your environment in one go:

Bash

git clone https://github.com/0x0smilex/smilex-eye.git && cd smilex-eye
Install the dependencies using the command below (the --break-system-packages flag is required to bypass environment restrictions on modern Linux systems like Kali or Ubuntu):

Bash

pip install -r requirements.txt --break-system-packages
To run the tool globally as a system command, execute this sequence:

Bash

mv smilex-eye.py smilex-eye && chmod +x smilex-eye && sudo mv smilex-eye /usr/local/bin/
[!WARNING] CRITICAL: Do NOT remove the Shebang line (#!/usr/bin/env python3) at the very top of the script. This line is mandatory for the system to execute the file as Python once the .py extension is removed.
