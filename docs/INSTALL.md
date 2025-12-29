Installation Guide
System Requirements

    Python 3.9 or higher

    Nmap 7.80 or higher

    Linux, macOS, or WSL (Windows Subsystem for Linux)

Installing Nmap
Ubuntu/Debian
bash

sudo apt update
sudo apt install nmap

macOS
bash

brew install nmap

Windows

Download from: https://nmap.org/download.html
Installing Python Dependencies
bash

# Clone repository
git clone https://github.com/yourusername/network-security-portfolio.git
cd network-security-portfolio

# Install (optional, as there are no Python dependencies yet)
pip install -r requirements.txt

Docker Installation
bash

# Build image
docker build -t network-scanner .

# Run scan
docker run -v $(pwd)/reports:/app/reports network-scanner \
  192.168.1.1 --profile discovery

