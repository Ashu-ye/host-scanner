#!/usr/bin/env python3
import platform
import socket
import subprocess
from queue import Empty, Queue
from threading import Lock, Thread

# Rich CLI components
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

# Scapy for ARP fallback / MAC discovery
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

console = Console()
ip_queue = Queue()
discovered_devices = []
results_lock = Lock()

# Common ports to probe
TARGET_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
}


def get_local_subnet() -> str:
    """Dynamically retrieves local network base subnet."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return ".".join(local_ip.split(".")[:-1]) + "."
    except Exception:
        return "192.168.1."


def resolve_hostname(ip: str) -> str:
    """Reverse DNS lookup for hostnames."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return "Unknown"


def scan_ports(ip: str) -> list:
    """Probes host for common open TCP ports."""
    open_ports = []
    for port, service in TARGET_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(f"{port}/{service}")
        except Exception:
            pass
    return open_ports


def get_mac_arp(ip: str) -> str:
    """Uses Scapy ARP request to obtain MAC addresses on local subnet."""
    if not SCAPY_AVAILABLE:
        return "N/A (Scapy missing)"
    try:
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        ans, _ = srp(ether / arp, timeout=0.8, verbose=False)
        for _, rcv in ans:
            return rcv.hwsrc
    except Exception:
        pass
    return "Unknown"


def ping_host(ip: str) -> bool:
    """Cross-platform ICMP ping check."""
    is_win = platform.system().lower() == "windows"
    is_mac = platform.system().lower() == "darwin"

    if is_win:
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    elif is_mac:
        cmd = ["ping", "-c", "1", "-W", "800", ip]
    else:  # Linux
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return res.returncode == 0


def worker(progress, task_id) -> None:
    """Worker thread processing the IP queue."""
    while True:
        try:
            ip = ip_queue.get(timeout=0.3)
        except Empty:
            break

        is_alive = ping_host(ip)

        # Fallback ARP check if ping fails or to grab MAC address
        mac = "Unknown"
        if SCAPY_AVAILABLE:
            mac_result = get_mac_arp(ip)
            if mac_result != "Unknown" and mac_result != "N/A (Scapy missing)":
                mac = mac_result
                is_alive = True  # Responded to ARP even if ICMP was blocked

        if is_alive:
            hostname = resolve_hostname(ip)
            open_ports = scan_ports(ip)

            device_info = {
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "ports": open_ports if open_ports else ["None Detected"],
            }

            with results_lock:
                discovered_devices.append(device_info)

        progress.advance(task_id)
        ip_queue.task_done()


def main() -> None:
    base_subnet = get_local_subnet()
    console.print(f"\n[bold cyan][*] Advanced Network Discovery Scanner[/bold cyan]")
    console.print(f"[*] Target Subnet: [yellow]{base_subnet}0/24[/yellow]\n")

    # Enqueue IPs 1-254
    for i in range(1, 255):
        ip_queue.put(f"{base_subnet}{i}")

    # Setup Progress Bar
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        scan_task = progress.add_task("[cyan]Scanning network hosts...", total=254)

        # Launch Threads
        threads = []
        for _ in range(40):
            t = Thread(target=worker, args=(progress, scan_task), daemon=True)
            t.start()
            threads.append(t)

        ip_queue.join()

    # Sort results by the 4th octet
    discovered_devices.sort(key=lambda d: int(d["ip"].split(".")[-1]))

    # Display Results in Terminal Table
    table = Table(title=f"\nActive Network Devices Found ({len(discovered_devices)})")
    table.add_column("IP Address", style="bold green")
    table.add_column("Hostname", style="bold yellow")
    table.add_column("MAC Address", style="bold magenta")
    table.add_column("Open Ports / Services", style="cyan")

    for dev in discovered_devices:
        table.add_row(
            dev["ip"],
            dev["hostname"],
            dev["mac"],
            ", ".join(dev["ports"]),
        )

    console.print(table)


if __name__ == "__main__":
    main()
