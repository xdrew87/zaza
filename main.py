import os
import sys
import json
import time
from datetime import datetime
import argparse
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from modules import ip_lookup, port_scan, dns_lookup, network_tools, abuse_check, virustotal_check, shodan_check
from utils.api_helpers import make_session
from utils.tor_control import rotate_tor_identity
from banner import get_banner

# GUI imports
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog

console = Console()

def print_banner():
    art, title = get_banner()
    console.print(Panel.fit(art, style="bold green", box=box.ROUNDED))
    console.print(f"[bold magenta]{title}[/bold magenta]\n")

def print_disclaimer():
    disclaimer = (
        "[bold yellow]Disclaimer:[/bold yellow] IPSentinel is for authorized security research only. "
        "Do not use for illegal activity. Respect privacy and laws."
    )
    console.print(disclaimer)

def save_json(data, fname=None):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = fname or f"ipsentinel_{ts}.json"
    with open(fname, "w") as f:
        json.dump(data, f, indent=2)
    console.print(f"[green]Results saved to {fname}[/green]")

def summarize_risk(results):
    risk = "Safe"
    if results.get("abuse", {}).get("score", 0) > 50 or results.get("vt", {}).get("malicious", 0) > 0:
        risk = "Malicious"
    elif results.get("abuse", {}).get("score", 0) > 10 or results.get("vt", {}).get("suspicious", 0) > 0:
        risk = "Suspicious"
    return risk

def about_text():
    return (
        "┌─────────────────────────────────────────────┐\n"
        "│              IPSentinel v1.0                │\n"
        "│─────────────────────────────────────────────│\n"
        "│ IPSentinel is a professional OSINT,         │\n"
        "│ network reconnaissance, and threat          │\n"
        "│ intelligence toolkit for security teams.    │\n"
        "│                                             │\n"
        "│ Designed for privacy, speed, and accuracy.  │\n"
        "│                                             │\n"
        "│ [!] For authorized security research only.  │\n"
        "│ [!] Do not use for illegal activity.        │\n"
        "│                                             │\n"
        "│ Project Home: https://github.com/yourrepo   │\n"
        "│ Author: github.com/xdrew87                  │\n"
        "│ Documentation: See included README.md       │\n"
        "│                                             │\n"
        "│ License: GNU General Public License v3.0    │\n"
        "└─────────────────────────────────────────────┘"
    )

def run_modules(args, session=None):
    results = {}
    target = args.ip or args.domain
    # Recon
    if args.ip:
        results["ip_lookup"] = ip_lookup.lookup(args.ip, session)
        results["reverse_dns"] = ip_lookup.reverse_dns(args.ip, session)
        if getattr(args, "geoip", False):
            results["geoip"] = ip_lookup.lookup(args.ip, session)
        if getattr(args, "whois", False):
            results["whois"] = ip_lookup.whois(args.ip)
        if getattr(args, "reverse", False):
            results["reverse"] = ip_lookup.reverse_dns(args.ip, session)
    if args.domain:
        results["domain_lookup"] = ip_lookup.domain_lookup(args.domain, session)
        if getattr(args, "whois", False):
            results["whois"] = ip_lookup.whois(args.domain)
        if getattr(args, "reverse", False):
            results["reverse"] = ip_lookup.reverse_dns(ip_lookup.domain_lookup(args.domain, session), session)
    if args.dns and args.domain:
        results["dns"] = dns_lookup.get_records(args.domain)
    # Ping/Traceroute
    if args.ping:
        results["ping"] = network_tools.ping(target)
    if args.traceroute:
        results["traceroute"] = network_tools.traceroute(target)
    # Port Scan
    if args.ip:
        start, end = map(int, args.ports.split("-"))
        results["ports"] = port_scan.scan(args.ip, start, end)
    # Threat Intel
    if args.abuse and args.ip:
        results["abuse"] = abuse_check.check(args.ip, session)
    if args.vt:
        results["vt"] = virustotal_check.check(target, session)
    if args.shodan and args.ip:
        results["shodan"] = shodan_check.check(args.ip, session)
    return results

def show_results_cli(results):
    table = Table(title="IPSentinel Results", box=box.SIMPLE)
    table.add_column("Module")
    table.add_column("Summary")
    for k, v in results.items():
        table.add_row(k, str(v)[:100])
    console.print(table)
    risk = summarize_risk(results)
    console.print(f"[bold cyan]Risk Assessment: {risk}[/bold cyan]")

def gui_main():
    root = tk.Tk()
    root.title("IPSentinel GUI")
    root.geometry("850x750")
    root.configure(bg="#23272e")

    # Banner & Header
    art, title = get_banner()
    header_frame = tk.Frame(root, bg="#23272e")
    header_frame.pack(fill="x", padx=0, pady=0)
    banner_label = tk.Label(header_frame, text=art, font=("Courier", 10), fg="#39ff14", bg="#23272e", justify="left")
    banner_label.pack(anchor="w", padx=10)
    title_label = tk.Label(header_frame, text=title, font=("Arial", 22, "bold"), fg="#ff00cc", bg="#23272e")
    title_label.pack(anchor="w", padx=10)
    subtitle_label = tk.Label(header_frame, text="OSINT | Network Recon | Threat Intelligence", font=("Arial", 12), fg="#00bfff", bg="#23272e")
    subtitle_label.pack(anchor="w", padx=10, pady=(0,10))

    # Target Section
    frame = ttk.LabelFrame(root, text="Target", padding=10)
    frame.pack(fill="x", padx=20, pady=5)
    ip_var = tk.StringVar()
    domain_var = tk.StringVar()
    ttk.Label(frame, text="IP:").grid(row=0, column=0, sticky="w")
    ip_entry = ttk.Entry(frame, textvariable=ip_var, width=22)
    ip_entry.grid(row=0, column=1, padx=5)
    ttk.Label(frame, text="Domain:").grid(row=0, column=2, sticky="w")
    domain_entry = ttk.Entry(frame, textvariable=domain_var, width=22)
    domain_entry.grid(row=0, column=3, padx=5)

    # Modules Section
    opts_frame = ttk.LabelFrame(root, text="Modules", padding=10)
    opts_frame.pack(fill="x", padx=20, pady=5)
    dns_var = tk.BooleanVar()
    ping_var = tk.BooleanVar()
    traceroute_var = tk.BooleanVar()
    abuse_var = tk.BooleanVar()
    vt_var = tk.BooleanVar()
    shodan_var = tk.BooleanVar()
    whois_var = tk.BooleanVar()
    geoip_var = tk.BooleanVar()
    reverse_var = tk.BooleanVar()
    port_var = tk.StringVar(value="1-1024")
    ttk.Checkbutton(opts_frame, text="DNS", variable=dns_var).grid(row=0, column=0, sticky="w")
    ttk.Checkbutton(opts_frame, text="Ping", variable=ping_var).grid(row=0, column=1, sticky="w")
    ttk.Checkbutton(opts_frame, text="Traceroute", variable=traceroute_var).grid(row=0, column=2, sticky="w")
    ttk.Checkbutton(opts_frame, text="AbuseIPDB", variable=abuse_var).grid(row=0, column=3, sticky="w")
    ttk.Checkbutton(opts_frame, text="VirusTotal", variable=vt_var).grid(row=0, column=4, sticky="w")
    ttk.Checkbutton(opts_frame, text="Shodan", variable=shodan_var).grid(row=0, column=5, sticky="w")
    ttk.Checkbutton(opts_frame, text="Whois", variable=whois_var).grid(row=1, column=0, sticky="w")
    ttk.Checkbutton(opts_frame, text="GeoIP", variable=geoip_var).grid(row=1, column=1, sticky="w")
    ttk.Checkbutton(opts_frame, text="Reverse", variable=reverse_var).grid(row=1, column=2, sticky="w")
    ttk.Label(opts_frame, text="Ports:").grid(row=2, column=0, sticky="w")
    port_entry = ttk.Entry(opts_frame, textvariable=port_var, width=10)
    port_entry.grid(row=2, column=1, padx=5, sticky="w")

    # Proxy/Tor Section
    proxy_frame = ttk.LabelFrame(root, text="Proxy & Tor", padding=10)
    proxy_frame.pack(fill="x", padx=20, pady=5)
    proxy_var = tk.StringVar()
    tor_var = tk.BooleanVar()
    ttk.Label(proxy_frame, text="Proxy URL:").grid(row=0, column=0, sticky="w")
    proxy_entry = ttk.Entry(proxy_frame, textvariable=proxy_var, width=32)
    proxy_entry.grid(row=0, column=1, padx=5)
    ttk.Checkbutton(proxy_frame, text="Use Tor", variable=tor_var).grid(row=0, column=2, sticky="w")

    # Output Section
    output_frame = tk.Frame(root, bg="#23272e")
    output_frame.pack(fill="both", expand=True, padx=20, pady=10)
    output_label = tk.Label(output_frame, text="Results", font=("Arial", 12, "bold"), fg="#39ff14", bg="#23272e")
    output_label.pack(anchor="w")
    output = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=22, font=("Consolas", 10), bg="#181a20", fg="#e6e6e6", insertbackground="#e6e6e6")
    output.pack(fill="both", expand=True, padx=0, pady=5)

    # Tooltip helper
    def tooltip(widget, text):
        tip = tk.Toplevel(widget)
        tip.withdraw()
        tip.overrideredirect(True)
        label = tk.Label(tip, text=text, background="#23272e", foreground="#39ff14", relief="solid", borderwidth=1, font=("Arial", 9))
        label.pack()
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 20
            tip.geometry(f"+{x}+{y}")
            tip.deiconify()
        def leave(event):
            tip.withdraw()
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    tooltip(ip_entry, "Enter target IP address")
    tooltip(domain_entry, "Enter target domain name")
    tooltip(proxy_entry, "Optional: HTTP/SOCKS proxy URL")
    tooltip(port_entry, "Port range (e.g. 1-1024)")

    # Actions
    def run_scan():
        ip = ip_var.get().strip()
        domain = domain_var.get().strip()
        if not ip and not domain:
            messagebox.showerror("Error", "Specify IP or Domain")
            return
        args = argparse.Namespace(
            ip=ip if ip else None,
            domain=domain if domain else None,
            ports=port_var.get(),
            dns=dns_var.get(),
            ping=ping_var.get(),
            traceroute=traceroute_var.get(),
            abuse=abuse_var.get(),
            vt=vt_var.get(),
            shodan=shodan_var.get(),
            whois=whois_var.get(),
            geoip=geoip_var.get(),
            reverse=reverse_var.get(),
            tor=tor_var.get(),
            proxy=proxy_var.get() if proxy_var.get() else None,
            timeout=10,
            retries=2
        )
        session = make_session(args.proxy if args.proxy else ("socks5h://127.0.0.1:9050" if args.tor else None))
        if args.tor:
            rotate_tor_identity()
        results = run_modules(args, session)
        output.delete(1.0, tk.END)
        output.insert(tk.END, json.dumps(results, indent=2))
        output.insert(tk.END, f"\nRisk Assessment: {summarize_risk(results)}\n")

    def export_results():
        data = output.get(1.0, tk.END)
        if not data.strip():
            messagebox.showinfo("Export", "No results to export.")
            return
        fname = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if fname:
            try:
                with open(fname, "w") as f:
                    f.write(data)
                messagebox.showinfo("Export", f"Results saved to {fname}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def show_about():
        about_win = tk.Toplevel(root)
        about_win.title("About IPSentinel")
        about_win.configure(bg="#23272e")
        about_win.geometry("500x380")
        tk.Label(about_win, text="IPSentinel", font=("Arial", 20, "bold"), fg="#ff00cc", bg="#23272e").pack(pady=10)
        tk.Label(
            about_win,
            text="A professional OSINT, network recon,\nand threat intelligence toolkit for security teams.",
            font=("Arial", 12), fg="#39ff14", bg="#23272e"
        ).pack(pady=5)
        tk.Label(
            about_win,
            text="Designed for privacy, speed, and accuracy.",
            font=("Arial", 10), fg="#00bfff", bg="#23272e"
        ).pack()
        tk.Label(
            about_win,
            text="[!] For authorized security research only.\n[!] Do not use for illegal activity.",
            font=("Arial", 10, "italic"), fg="#ff0000", bg="#23272e"
        ).pack(pady=10)
        tk.Label(
            about_win,
            text="Project Home: https://github.com/yourrepo",
            font=("Arial", 10), fg="#e6e6e6", bg="#23272e"
        ).pack()
        tk.Label(
            about_win,
            text="Author: github.com/xdrew87",
            font=("Arial", 10), fg="#e6e6e6", bg="#23272e"
        ).pack()
        tk.Label(
            about_win,
            text="Documentation: See included README.md",
            font=("Arial", 10), fg="#e6e6e6", bg="#23272e"
        ).pack()
        tk.Label(
            about_win,
            text="License: GNU General Public License v3.0",
            font=("Arial", 10, "italic"), fg="#39ff14", bg="#23272e"
        ).pack(pady=5)
        tk.Button(
            about_win, text="Close", command=about_win.destroy,
            bg="#39ff14", fg="#23272e", font=("Arial", 10, "bold")
        ).pack(pady=10)

    def clear_output():
        output.delete(1.0, tk.END)

    def copy_output():
        root.clipboard_clear()
        root.clipboard_append(output.get(1.0, tk.END))
        messagebox.showinfo("Copy", "Results copied to clipboard.")

    def show_banner():
        messagebox.showinfo("Banner", art)

    # Button Section
    btn_frame = tk.Frame(root, bg="#23272e")
    btn_frame.pack(fill="x", padx=20, pady=10)
    tk.Button(btn_frame, text="Run", command=run_scan, bg="#39ff14", fg="#23272e", font=("Arial", 10, "bold"), width=10).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Export", command=export_results, bg="#00bfff", fg="#23272e", font=("Arial", 10, "bold"), width=10).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Copy", command=copy_output, bg="#ff00cc", fg="#23272e", font=("Arial", 10, "bold"), width=10).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Clear", command=clear_output, bg="#e6e6e6", fg="#23272e", font=("Arial", 10, "bold"), width=10).pack(side="left", padx=5)
    tk.Button(btn_frame, text="Banner", command=show_banner, bg="#23272e", fg="#39ff14", font=("Arial", 10, "bold"), width=10).pack(side="left", padx=5)
    tk.Button(btn_frame, text="About", command=show_about, bg="#23272e", fg="#00bfff", font=("Arial", 10, "bold"), width=10).pack(side="left", padx=5)

    root.mainloop()

def main():
    print_banner()
    print_disclaimer()

    parser = argparse.ArgumentParser(description="IPSentinel: OSINT & Threat Intelligence CLI")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-p", "--ports", help="Port range (e.g. 1-1024)", default="1-1024")
    parser.add_argument("--dns", action="store_true", help="Show DNS records")
    parser.add_argument("--ping", action="store_true", help="Ping target")
    parser.add_argument("--traceroute", action="store_true", help="Traceroute target")
    parser.add_argument("--abuse", action="store_true", help="Check AbuseIPDB")
    parser.add_argument("--vt", action="store_true", help="Check VirusTotal")
    parser.add_argument("--shodan", action="store_true", help="Check Shodan")
    parser.add_argument("--whois", action="store_true", help="Show Whois info")
    parser.add_argument("--geoip", action="store_true", help="Show GeoIP info")
    parser.add_argument("--reverse", action="store_true", help="Show Reverse DNS")
    parser.add_argument("--tor", action="store_true", help="Route via Tor")
    parser.add_argument("--proxy", help="Proxy URL (http/socks)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout seconds")
    parser.add_argument("--retries", type=int, default=2, help="Retries for API calls")
    parser.add_argument("--about", action="store_true", help="Show about info")
    parser.add_argument("--gui", action="store_true", help="Launch GUI")
    parser.add_argument("--export", help="Export results to filename")
    parser.add_argument("--banner", action="store_true", help="Show banner art")
    parser.add_argument("--clear", action="store_true", help="Clear output")
    parser.add_argument("--copy", action="store_true", help="Copy output to clipboard")
    args = parser.parse_args()

    if args.about:
        console.print(about_text())
        sys.exit(0)
    if args.banner:
        art, _ = get_banner()
        console.print(Panel.fit(art, style="bold green", box=box.ROUNDED))
        sys.exit(0)
    if args.gui:
        gui_main()
        sys.exit(0)
    if args.clear:
        os.system('cls' if os.name == 'nt' else 'clear')
        sys.exit(0)

    # Input validation
    target = args.ip or args.domain
    if not target:
        console.print("[red]Error: Specify --ip or --domain[/red]")
        sys.exit(1)
    if args.ip and not ip_lookup.is_valid_ip(args.ip):
        console.print("[red]Error: Invalid IP address[/red]")
        sys.exit(1)
    if args.domain and not ip_lookup.is_valid_domain(args.domain):
        console.print("[red]Error: Invalid domain[/red]")
        sys.exit(1)

    # Proxy/Tor session
    session = make_session(args.proxy if args.proxy else ("socks5h://127.0.0.1:9050" if args.tor else None))

    if args.tor:
        rotate_tor_identity()

    results = run_modules(args, session)
    show_results_cli(results)

    if args.copy:
        import pyperclip
        pyperclip.copy(json.dumps(results, indent=2))
        console.print("[green]Results copied to clipboard.[/green]")

    save_json(results, args.export if args.export else None)

if __name__ == "__main__":
    main()
