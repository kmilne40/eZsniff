#!/usr/bin/env python3
import argparse
import json
import re
import sys
import time
import datetime
import signal
import ipaddress   # For IP validation
import requests

try:
    from scapy.all import (
        sniff,
        wrpcap,
        TCP,
        IP
    )
except ImportError:
    print("Scapy is not installed. Please install it via pip: pip install scapy")
    sys.exit(1)

###############################################################################
# EBCDIC/3270 pattern and ANSI colouring
###############################################################################

EBCDIC_REGEX = re.compile(b"\x7d..\x11..(.*)\x40*\xff\xef$")
RED = "\033[91m"
RESET = "\033[0m"

# We'll store IP-specific geolocation and port data here
ip_geo_data = {}

###############################################################################
# Validate IP address
###############################################################################

def is_valid_ip(ip):
    """
    Validate an IPv4 or IPv6 address using ipaddress.
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

###############################################################################
# Geolocation (via freeipapi.com)
###############################################################################

def get_geolocation(ip):
    """
    Fetch geolocation data for a given IP address using freeipapi.com.
    Returns a dict if successful, or None if unable to fetch.
    """
    url = f"https://freeipapi.com/api/json/{ip}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raise if HTTP status != 200
        data = response.json()

        if data.get('status') == 'fail':
            print(f"Failed to retrieve data for IP {ip}: {data.get('message')}")
            return None
        
        return data
    except requests.exceptions.Timeout:
        print(f"Request timed out for IP {ip}.")
        return None
    except requests.exceptions.ConnectionError:
        print(f"Connection error occurred while fetching data for IP {ip}.")
        return None
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred for IP {ip}: {http_err}")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON response for IP {ip}.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred for IP {ip}: {e}")
        return None

###############################################################################
# Load malicious IPs
###############################################################################

def load_malicious_ips(malicious_ip_file):
    """
    Load malicious IPs from a JSON file with a structure like:
      {
        "malicious_ips": [
          "192.168.1.10",
          "10.0.0.7"
        ]
      }
    Returns a set of IP strings considered malicious.
    """
    if not malicious_ip_file:
        return set()
    try:
        with open(malicious_ip_file, "r") as f:
            data = json.load(f)
            return set(data.get("malicious_ips", []))
    except Exception as e:
        print(f"Error loading malicious IP file: {e}")
        return set()

###############################################################################
# Default interface (Linux)
###############################################################################

def get_default_iface_name_linux():
    """
    Attempt to determine the default gateway interface on Linux 
    by reading /proc/net/route.
    """
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines():
                try:
                    iface, dest, _, flags, _, _, _, _, _, _, _, = line.strip().split()
                    # Check for default route (dest == '00000000') and 'UP' & 'GATEWAY' flags
                    if dest != '00000000' or not int(flags, 16) & 2:
                        continue
                    return iface
                except:
                    continue
    except FileNotFoundError:
        pass
    return None

###############################################################################
# Port class
###############################################################################

class Port(int):
    """
    A Network Port (i.e., 0 < integer <= 65535)
    """
    def __new__(cls, val, *args, **kwargs):
        new_int = int.__new__(cls, val, *args, **kwargs)
        if not 0 < new_int <= 65535:
            raise ValueError("Port out of range: %d" % new_int)
        return new_int

###############################################################################
# Payload parsing (ASCII/EBCDIC)
###############################################################################

def parse_ascii(payload):
    """
    Attempt to decode payload as ASCII, replacing non-ASCII bytes.
    Returns the decoded string or None if blank after stripping.
    """
    text = payload.decode('ascii', errors='replace')
    if text.strip():
        return text
    return None

def parse_ebcdic(payload):
    """
    Attempt to match and decode 3270-like EBCDIC data.
    Returns the decoded string or None if no match.
    """
    match = re.search(EBCDIC_REGEX, payload)
    if match:
        try:
            ebcdic_text = match.group(1).decode('cp500', errors='replace')
            if ebcdic_text.strip():
                return ebcdic_text
        except UnicodeDecodeError:
            pass
    return None

###############################################################################
# Packet callback
###############################################################################

def combined_callback(packet, malicious_ips, modes, seen_ips):
    """
    Unified callback for ASCII/EBCDIC traffic:
      - Extracts IP/TCP layer
      - Prints IP, port, geolocation, and connection time on first contact
      - Parses ASCII/EBCDIC if requested
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        payload = bytes(packet[TCP].payload)

        # Only process new IPs for "first contact" info
        if src_ip not in seen_ips:
            # Malicious or not
            if src_ip in malicious_ips:
                print(f"{RED}[!] Malicious IP connection: {src_ip} on port {dst_port}{RESET}")
            else:
                print(f"Incoming connection from: {src_ip} on port {dst_port}")

            # Validate IP and get geolocation
            if not is_valid_ip(src_ip):
                print(" - Invalid IP format (skipping geolocation)")
                geo_info = None
            else:
                geo_info = get_geolocation(src_ip)

            # Connection time
            connection_time = datetime.datetime.fromtimestamp(packet.time)

            if geo_info:
                # freeipapi returns different keys vs. ip-api
                country = geo_info.get("countryName")
                region = geo_info.get("regionName")
                city = geo_info.get("cityName")
                lat = geo_info.get("latitude")
                lon = geo_info.get("longitude")
                
                if country or region or city:
                    print(f" - Geolocation: {city}, {region}, {country}")
                else:
                    print(" - Geolocation: Not available")
            else:
                country = region = city = lat = lon = None
                print(" - Geolocation: Not available")

            print(f" - Connection time: {connection_time}")

            # Store data for map generation
            ip_geo_data[src_ip] = {
                "time": connection_time,
                "country": country,
                "region": region,
                "city": city,
                "lat": lat,
                "lon": lon,
                "port": dst_port
            }

            seen_ips.add(src_ip)

        # Parse payload if requested
        if not payload:
            return

        if "ascii" in modes:
            ascii_text = parse_ascii(payload)
            if ascii_text is not None:
                print(f"[ASCII] {ascii_text}")

        if "ebcdic" in modes:
            ebcdic_text = parse_ebcdic(payload)
            if ebcdic_text is not None:
                print(f"[EBCDIC] {ebcdic_text}")

###############################################################################
# Map generation
###############################################################################

def generate_map():
    """
    Generate a geolocation map (using Folium) of all encountered IPs.
      - NK, China, Russia, Iran -> red
      - US, UK -> blue
      - Others -> green
    Shows IP, port, city, region, country, and connection time in a popup.
    """
    try:
        import folium
    except ImportError:
        print("The 'folium' module is not installed. Please install it via pip: pip install folium")
        return

    print("\nGenerating geolocation map...")

    world_map = folium.Map(location=[20, 0], zoom_start=2)

    for ip_addr, data in ip_geo_data.items():
        lat = data.get("lat")
        lon = data.get("lon")
        country = data.get("country")
        port = data.get("port", "Unknown")

        if lat is None or lon is None:
            continue

        # Decide marker colour by country
        if country in ["North Korea", "China", "Russia", "Iran"]:
            marker_colour = "red"
        elif country in ["United States", "United Kingdom"]:
            marker_colour = "blue"
        else:
            marker_colour = "green"

        popup_text = (f"IP: {ip_addr}<br>"
                      f"Port: {port}<br>"
                      f"City: {data.get('city', 'Unknown')}<br>"
                      f"Region: {data.get('region', 'Unknown')}<br>"
                      f"Country: {country}<br>"
                      f"Time: {data.get('time')}")

        folium.Marker(
            location=[lat, lon],
            popup=popup_text,
            icon=folium.Icon(color=marker_colour)
        ).add_to(world_map)

    world_map.save("geolocation_map.html")
    print("Map has been saved to geolocation_map.html.")

###############################################################################
# Sniffers
###############################################################################

def sniff_combined(target, ports, interface, malicious_ips, modes):
    """
    Capture traffic for the given target and ports using 'combined_callback'.
    """
    ports_filter = " or ".join([f"port {p}" for p in ports])
    filter_str = f"host {target} and tcp and ({ports_filter})"

    print(f"Starting capture on interface '{interface}' for {target}:{ports}")
    print(f"Modes: {', '.join(modes)}")
    print("Press Ctrl+C or Ctrl+Z to stop...\n")

    seen_ips = set()

    try:
        packets = sniff(
            filter=filter_str,
            iface=interface,
            prn=lambda pkt: combined_callback(pkt, malicious_ips, modes, seen_ips)
        )
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Sniffing error: {e}")

    wrpcap("traffic.pcap", packets)
    print("Done! Packets saved to traffic.pcap.")
    generate_map()

def sniff_tls(interface):
    """
    Sniffs TLS (port 443) traffic on the specified interface.
    """
    filter_str = "tcp and port 443"

    def tls_packet_callback(packet):
        print("TLS packet captured (likely encrypted).")

    print(f"Starting TLS capture on interface='{interface}', port=443")
    print("Press Ctrl+C or Ctrl+Z to stop...\n")

    try:
        packets = sniff(filter=filter_str, iface=interface, prn=tls_packet_callback)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Sniffing error: {e}")

    wrpcap("tls_traffic.pcap", packets)
    print("Done! TLS packets saved to tls_traffic.pcap.")
    generate_map()

###############################################################################
# SIGTSTP Handling (Ctrl+Z)
###############################################################################

def handle_sigTSTP(signum, frame):
    print("\nSIGTSTP (Ctrl+Z) caught. Generating map and exiting...")
    generate_map()
    sys.exit(0)

signal.signal(signal.SIGTSTP, handle_sigTSTP)

###############################################################################
# Main
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="Packet Sniffer with Geolocation (ASCII, EBCDIC, or TLS)."
    )
    parser.add_argument(
        "TARGET",
        help="Target IP for sniffing (omit if --tls is used).",
        nargs="?",
        default=None
    )
    parser.add_argument(
        "-p", "--ports",
        help="One or more target ports (Default: 3270). Example: -p 23 3270 80",
        nargs="+",
        default=["3270"],
        type=Port
    )
    parser.add_argument(
        "-i", "--iface",
        help="Network interface to use (default: tries to detect).",
        default=get_default_iface_name_linux()
    )
    parser.add_argument(
        "-m", "--modes",
        help="Traffic parsing modes: ascii, ebcdic, or both. Example: -m ascii ebcdic",
        nargs="+",
        default=["ebcdic"],
        choices=["ebcdic", "ascii"]
    )
    parser.add_argument(
        "--tls", action="store_true",
        help="Capture TLS traffic on port 443 instead of EBCDIC/ASCII."
    )
    parser.add_argument(
        "--malicious-ip-file",
        help="Path to JSON file with malicious IPs. (Default: None)",
        default=None
    )
    args = parser.parse_args()

    # Load malicious IPs from file if provided
    malicious_ips = load_malicious_ips(args.malicious_ip_file)

    # If TLS is specified, we ignore normal target/ports
    if args.tls:
        if not args.iface:
            print("Could not determine default interface; please specify -i <interface>.")
            sys.exit(1)
        sniff_tls(args.iface)
    else:
        if not args.TARGET:
            print("Error: You must specify a TARGET unless you use --tls.")
            sys.exit(1)
        if not args.iface:
            print("Could not determine default interface; please specify -i <interface>.")
            sys.exit(1)
        sniff_combined(
            target=args.TARGET,
            ports=args.ports,
            interface=args.iface,
            malicious_ips=malicious_ips,
            modes=args.modes
        )

if __name__ == "__main__":
    main()
