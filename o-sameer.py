#!/usr/bin/env python3
# === Auto install required Python packages ===
import subprocess
import sys

required = ['scapy', 'rich', 'simple-term-menu']
for package in required:
    try:
        __import__(package.replace('-', '_'))
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# === Imports ===
import os
import time
import random
import asyncio
import threading
import signal
import atexit
from scapy.all import *
from simple_term_menu import TerminalMenu
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

console = Console()
selected_interface = None

# === Banner ===
BANNER = r"""
:'#######::::::'######:::::'###::::'##::::'##:'########:'########:'########::
'##.... ##::::'##... ##:::'## ##::: ###::'###: ##.....:: ##.....:: ##.... ##:
##:::: ##:::: ##:::..:::'##:. ##:: ####'####: ##::::::: ##::::::: ##:::: ##:
##:::: ##::::. ######::'##:::. ##: ## ### ##: ######::: ######::: ########::
##:::: ##:::::..... ##: #########: ##. #: ##: ##...:::: ##...:::: ##.. ##:::
##:::: ##::::'##::: ##: ##.... ##: ##:.:: ##: ##::::::: ##::::::: ##::. ##::
. #######:::::. ######:: ##:::: ##: ##:::: ##: ########: ########: ##:::. ##:
:.......:::::::......:::..:::::..::..:::::..::........::........::..:::::..::
"""

# === Cleanup ===
def cleanup():
    if selected_interface:
        console.print(f"\n[cyan]Restoring {selected_interface} to managed mode...[/cyan]")
        try:
            set_managed_mode(selected_interface)
        except Exception as e:
            console.print(f"[red]Failed to restore interface: {e}[/red]")

atexit.register(cleanup)

def signal_handler(sig, frame):
    console.print("\n[red]Interrupted! Returning interface to normal mode.[/red]")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# === Wi-Fi mode management ===
def is_interface_up(interface):
    try:
        state = open(f"/sys/class/net/{interface}/operstate").read().strip()
        return state == "up"
    except:
        return False

def get_wifi_interfaces():
    output = os.popen("iw dev | grep Interface").read().splitlines()
    return [line.strip().split()[-1] for line in output]

def ensure_interface_up(interface):
    os.system(f"sudo ip link set {interface} up")
    for _ in range(10):
        if is_interface_up(interface):
            return True
        time.sleep(0.5)
    return False

def stop_conflicting_services():
    console.print("[yellow]Stopping NetworkManager and wpa_supplicant...[/yellow]")
    os.system("sudo systemctl stop NetworkManager")
    os.system("sudo systemctl stop wpa_supplicant")

def start_conflicting_services():
    console.print("[yellow]Starting NetworkManager and wpa_supplicant...[/yellow]")
    os.system("sudo systemctl start NetworkManager")
    os.system("sudo systemctl start wpa_supplicant")

def set_monitor_mode(interface):
    stop_conflicting_services()
    console.print(f"[yellow]Switching {interface} to monitor mode...[/yellow]")
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw dev {interface} set type monitor")
    if not ensure_interface_up(interface):
        console.print(f"[red]Retrying monitor mode on {interface}...[/red]")
        os.system(f"sudo ip link set {interface} down")
        os.system(f"sudo iw dev {interface} set type managed")
        os.system(f"sudo ip link set {interface} up")
        time.sleep(1)
        os.system(f"sudo ip link set {interface} down")
        os.system(f"sudo iw dev {interface} set type monitor")
        if not ensure_interface_up(interface):
            console.print(f"[bold red]Monitor mode failed.[/bold red]")
            os.system("iw dev")
            sys.exit(1)

def set_managed_mode(interface):
    os.system(f"sudo ip link set {interface} down")
    os.system(f"sudo iw dev {interface} set type managed")
    os.system(f"sudo ip link set {interface} up")
    start_conflicting_services()

def channel_hopper(interface, stop_event):
    while not stop_event.is_set():
        channel = random.randint(1, 13)
        os.system(f"iw dev {interface} set channel {channel}")
        time.sleep(0.5)

# === Scan networks ===
async def print_banner():
    console.clear()
    console.print(f"[cyan]{BANNER}[/cyan]")

async def async_scan_networks(interface, scan_time=15):
    console.print(f"Scanning Wi-Fi networks on: [bold]{interface}[/bold] for {scan_time} seconds...")

    networks = {}
    stop_event = threading.Event()
    hopper_thread = threading.Thread(target=channel_hopper, args=(interface, stop_event))
    hopper_thread.start()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
            ssid = pkt[Dot11Elt].info.decode(errors='ignore')
            bssid = pkt[Dot11].addr3
            if ssid and bssid and bssid not in networks:
                networks[bssid] = ssid

    try:
        sniff(iface=interface, prn=packet_handler, timeout=scan_time)
    except OSError as e:
        console.print(f"[red]Sniff failed: {e}[/red]")
        stop_event.set()
        hopper_thread.join()
        return []

    stop_event.set()
    hopper_thread.join()

    if not networks:
        console.print("[red]No networks found![/red]")
        return []

    return [{"ssid": ssid, "bssid": bssid} for bssid, ssid in networks.items()]

# === Crack WPA with progress ===
async def start_attack(target, interface, wordlist):
    while True:
        console.print(f"\n[bold green]Target:[/bold green] {target['ssid']} | {target['bssid']}")
        console.print(f"[yellow]Using wordlist:[/yellow] {wordlist}")

        console.print("\n[bold blue]Capturing handshake...[/bold blue]")
        await asyncio.sleep(3)
        console.print("[bold green]Handshake captured![/bold green] Cracking...\n")

        try:
            with open(wordlist, 'r') as f:
                passwords = f.read().splitlines()
        except FileNotFoundError:
            console.print(f"[red]Wordlist not found: {wordlist}[/red]")
            return

        total = len(passwords)
        found = False

        with Progress(
            SpinnerColumn(),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TextColumn("{task.completed}/{task.total} tried"),
            TimeRemainingColumn(),
            TextColumn(" | {task.description}")
        ) as progress:
            task = progress.add_task("Cracking password...", total=total)

            for password in passwords:
                await asyncio.sleep(0.1)
                if password == "sameer123":  # Mock correct password
                    console.print(f"\n[bold green]Password found: {password}[/bold green]")
                    found = True
                    break
                progress.advance(task)

        if found:
            return

        console.print("\n[red]Password not found in the list.[/red]\n")
        retry_menu = TerminalMenu(["Yes", "No"], title="Do you want to try a custom password list?")
        choice = retry_menu.show()

        if choice == 0:
            wordlist = console.input("\nEnter full path to custom wordlist: ")
        else:
            console.print("\n[red]Then why did you select the built-in list? 🤔[/red]")
            return

# === Main app ===
async def main():
    global selected_interface
    await print_banner()

    interfaces = get_wifi_interfaces()
    if not interfaces:
        console.print("[red]No Wi-Fi interfaces found.[/red]")
        sys.exit(1)

    menu = TerminalMenu(interfaces, title="Select your Wi-Fi interface:")
    index = menu.show()
    selected_interface = interfaces[index]

    set_monitor_mode(selected_interface)

    try:
        networks = await async_scan_networks(selected_interface, scan_time=20)
        if not networks:
            return

        choices = [f"{net['ssid']} | BSSID: {net['bssid']}" for net in networks]
        terminal_menu = TerminalMenu(choices, title="Select target Wi-Fi network:")
        idx = terminal_menu.show()
        target = networks[idx]

        mode_menu = TerminalMenu(["Use built-in wordlist (bild.txt)", "Use custom wordlist"], title="Choose cracking mode")
        mode = mode_menu.show()

        wordlist_path = "bild.txt" if mode == 0 else console.input("\nEnter path to wordlist: ")
        await start_attack(target, selected_interface, wordlist_path)

    finally:
        cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        cleanup()
        sys.exit(0)