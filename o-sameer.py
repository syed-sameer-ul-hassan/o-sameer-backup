#!/usr/bin/env python3
import asyncio
import os
import sys
from scapy.all import *
from simple_term_menu import TerminalMenu
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

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

console = Console()

async def print_banner():
    console.clear()
    console.print(f"[cyan]{BANNER}[/cyan]")

async def detect_wireless_interfaces():
    # Use 'iw dev' command to detect wireless interfaces in managed mode
    proc = await asyncio.create_subprocess_shell(
        "iw dev | grep Interface",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await proc.communicate()
    interfaces = []
    for line in stdout.decode().splitlines():
        iface = line.strip().split()[-1]
        interfaces.append(iface)
    return interfaces

async def async_scan_networks(interface, scan_time=15):
    """Async scanning using scapy"""
    console.print(f"Scanning Wi-Fi networks on interface: [bold]{interface}[/bold] for {scan_time} seconds...\n")
    networks = {}

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

    # Return list of dicts with ssid and bssid
    return [{"ssid": ssid, "bssid": bssid} for bssid, ssid in networks.items()]

async def main():
    await print_banner()
    # Detect interfaces
    interfaces = await detect_wireless_interfaces()
    if not interfaces:
        console.print("[red]No wireless interfaces found! Exiting.[/red]")
        sys.exit(1)

    # Let user select interface
    terminal_menu = TerminalMenu(interfaces, title="Select wireless interface:")
    index = terminal_menu.show()
    interface = interfaces[index]

    # Scan networks async
    networks = await async_scan_networks(interface)
    if not networks:
        sys.exit(1)

    # Select target network
    choices = [f"{net['ssid']} | BSSID: {net['bssid']}" for net in networks]
    terminal_menu = TerminalMenu(choices, title="Select target Wi-Fi network:")
    idx = terminal_menu.show()
    target = networks[idx]

    console.print(f"\nSelected Target: [bold]{target['ssid']}[/bold] | BSSID: {target['bssid']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Exiting...[/red]")
