# IPSentinel

A professional OSINT, network reconnaissance, and threat intelligence toolkit for Kali Linux.

## Features

- IP lookup: ASN, ISP, org, geolocation, reverse DNS
- Domain lookup and DNS records (A, MX, TXT, NS)
- Multi-threaded TCP port scanning
- Ping and traceroute
- Threat intelligence: AbuseIPDB, VirusTotal, Shodan
- Proxy and Tor support for privacy
- CLI and GUI (Tkinter) interfaces
- Rich colored output and JSON export
- Risk assessment summary (Safe / Suspicious / Malicious)
- Input validation and error handling
- API keys loaded from `.env`
- Responsible use disclaimer

## License

IPSentinel is licensed under the GNU General Public License v3.0 (GPLv3).

You may copy, modify, and redistribute this software under the terms of the GPLv3.  
See [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html) for details.

## GUI
<img width="697" height="764" alt="Screenshot 2025-09-07 190835" src="https://github.com/user-attachments/assets/6a082629-37da-4738-8995-ba64c47bd74d" />

## Installation

1. Clone the repository:
    ```
    git clone https://github.com/xdrew87/zaza.git
    cd zaza
    ```
2. Install dependencies:
    ```
    pip install -r requirements.txt
    ```
3. Create a `.env` file with your API keys:
    ```
    ABUSEIPDB_KEY=your_abuseipdb_api_key
    VT_KEY=your_virustotal_api_key
    SHODAN_KEY=your_shodan_api_key
    ```

## Usage

### CLI
<img width="769" height="504" alt="Screenshot 2025-09-07 190907" src="https://github.com/user-attachments/assets/b7d58a7d-4ded-4e25-9437-ea1c1dfe4caa" />


```
python main.py -i <ip> [options]
python main.py -d <domain> [options]
```

#### Common Options

- `-p 1-1024`         Port range
- `--dns`             DNS records
- `--ping`            Ping target
- `--traceroute`      Traceroute target
- `--abuse`           AbuseIPDB check
- `--vt`              VirusTotal check
- `--shodan`          Shodan check
- `--whois`           Whois info
- `--geoip`           GeoIP info
- `--reverse`         Reverse DNS
- `--tor`             Route via Tor
- `--proxy <url>`     Use proxy
- `--timeout <sec>`   Timeout (default: 10)
- `--retries <n>`     Retries (default: 2)
- `--export <file>`   Export results to JSON
- `--banner`          Show ASCII banner
- `--about`           Show about info
- `--gui`             Launch GUI

### GUI

Launch with:
```
python main.py --gui
```
- Enter IP or domain, select modules, configure proxy/Tor, and run scans.
- Export, copy, and clear results with buttons.
- View About and banner from the GUI.

## API Keys

Set your keys in `.env`:
```
ABUSEIPDB_KEY=...
VT_KEY=...
SHODAN_KEY=...
```

## Security & Disclaimer

- IPSentinel is for authorized security research only.
- Do not use for illegal activity.
- All API calls use HTTPS.
- Input is validated for safety.
- Use responsibly and respect privacy and laws.

## Support

For help, open an issue on GitHub or see the included documentation.

---




