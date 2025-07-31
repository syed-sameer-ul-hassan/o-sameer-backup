#!/usr/bin/env python3 import os import sys import asyncio from scapy.all import * from simple_term_menu import TerminalMenu from rich.console import Console from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

BANNER = r""" :'#######::::::'######:::::'###::::'##::::'##:'########:'########:'########:: '##.... ##::::'##... ##:::'## ##::: ###::'###: ##.....:: ##.....:: ##.... ##: ##:::: ##:::: ##:::..:::'##:. ##:: ####'####: ##::::::: ##::::::: ##:::: ##: ##:::: ##::::. ######::'##:::. ##: ## ### ##: ######::: ######::: ########:: ##:::: ##:::::..... ##: #########: ##. #: ##: ##...:::: ##...:::: ##.. ##::: ##:::: ##::::'##::: ##: ##.... ##: ##:.:: ##: ##::::::: ##::::::: ##::. ##:: . #######:::::. ######:: ##:::: ##: ##:::: ##: ########: ########: ##:::. ##: :.......:::::::......:::..:::::..::..:::::..::........::........::..:::::..:: """

console = Console()

Ensure interface is in monitor mode

def set_monitor_mode(interface): os.system(f"sudo ip link set {interface} down") os.system(f"sudo iw dev {interface} set type monitor") os.system(f"sudo ip link set {interface} up")

Return to managed mode

def set_managed_mode(interface): os.system(f"sudo ip link set {interface} down") os.system(f"sudo iw dev {interface} set type managed") os.system(f"sudo ip link set {interface} up")

async def print_banner(): console.clear() console.print(f"[cyan]{BANNER}[/cyan]")

async def detect_monitor_interfaces(): proc = await asyncio.create_subprocess_shell( "iw dev", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE ) stdout, _ = await proc.communicate() interfaces = [] current_iface = None for line in stdout.decode().splitlines(): if "Interface" in line: current_iface = line.strip().split()[-1] if "type monitor" in line and current_iface: interfaces.append(current_iface) return interfaces

async def async_scan_networks(interface, scan_time=15): console.print(f"Scanning Wi-Fi networks on: [bold]{interface}[/bold] for {scan_time} seconds...") networks = {}

def packet_handler(pkt):
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        ssid = pkt[Dot11Elt].info.decode(errors='ignore')
        bssid = pkt[Dot11].addr3
        if ssid and bssid:
            networks[bssid] = ssid

sniff(iface=interface, prn=packet_handler, timeout=scan_time)

if not networks:
    console.print("[red]No networks found![/red]")
    return []

return [{"ssid": ssid, "bssid": bssid} for bssid, ssid in networks.items()]

async def start_attack(target, interface, wordlist): console.print(f"\n[bold green]Starting attack on:[/bold green] {target['ssid']} | {target['bssid']}") console.print(f"[yellow]Using wordlist:[/yellow] {wordlist}")

console.print("\n[bold blue]Simulating WPA handshake capture...[/bold blue]")
await asyncio.sleep(3)

console.print("[bold green]Handshake captured![/bold green] Starting password cracking...\n")

with open(wordlist, 'r') as f:
    passwords = f.read().splitlines()

with Progress(SpinnerColumn(), BarColumn(), TextColumn("{task.description}")) as progress:
    task = progress.add_task("Cracking password...", total=len(passwords))

    for password in passwords:
        await asyncio.sleep(0.1)
        if password == "sameer123":  # Simulated correct password
            console.print(f"\n[bold green]Password found: {password}[/bold green]")
            return
        progress.advance(task)

console.print("\n[red]Password not found in the list.[/red]")

async def main(): await print_banner()

interfaces = await detect_monitor_interfaces()
if not interfaces:
    console.print("[red]No monitor interfaces found. Please enable monitor mode first.[/red]")
    sys.exit(1)

terminal_menu = TerminalMenu(interfaces, title="Select Wi-Fi interface:")
index = terminal_menu.show()
interface = interfaces[index]

set_monitor_mode(interface)

networks = await async_scan_networks(interface)
if not networks:
    set_managed_mode(interface)
    sys.exit(1)

choices = [f"{net['ssid']} | BSSID: {net['bssid']}" for net in networks]
terminal_menu = TerminalMenu(choices, title="Select target Wi-Fi network:")
idx = terminal_menu.show()
target = networks[idx]

mode_menu = TerminalMenu(["Use built-in wordlist (bild.txt)", "Use custom wordlist"], title="Choose cracking mode")
mode = mode_menu.show()

if mode == 0:
    wordlist_path = "bild.txt"
else:
    wordlist_path = console.input("\nEnter full path to custom wordlist: ")

await start_attack(target, interface, wordlist_path)
set_managed_mode(interface)
console.print("\n[cyan]Interface returned to managed mode.[/cyan]")

if name == "main": try: asyncio.run(main()) except KeyboardInterrupt: console.print("\n[red]Exiting...[/red]") try: set_managed_mode("wlan0") except: pass

