# DNS Tunneling Detection

A Python-based tool for detecting potential DNS tunneling activities by monitoring and analyzing DNS traffic.

## Features

- Captures and analyzes DNS traffic in real-time
- Logs DNS queries for further analysis
- Detects potential DNS tunneling attempts
- Lightweight and easy to use

## Prerequisites

- Python 3.6 or higher
- Administrator/root privileges (for packet capture)
- Required Python packages (install using `pip install -r requirements.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/sharath-gowda-g/dns-tunnling-detection.git
   cd dns-tunnling-detection
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the DNS logger with administrator/root privileges:
   ```bash
   sudo python dns_logger.py
   ```
   On Windows, run Command Prompt as Administrator and then execute the script.

2. The script will start capturing DNS traffic and log it to `dns_log.txt` in the same directory.

3. Monitor the console output for any suspicious DNS activities.

## How It Works

The script captures DNS packets and analyzes them for potential tunneling activities by:
- Monitoring unusually long domain names
- Tracking excessive DNS queries to the same domain
- Looking for patterns typical in DNS tunneling

## Configuration

You can modify the following parameters in `dns_logger.py`:
- `INTERFACE`: Network interface to monitor (default: automatically detects)
- `LOG_FILE`: Path to the log file (default: 'dns_log.txt')
- `THRESHOLD`: Threshold for detecting suspicious activities

## Log File Format

The log file (`dns_log.txt`) contains the following information for each DNS query:
- Timestamp
- Source IP
- Destination IP
- Query Type
- Domain Name
- Response Status

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
