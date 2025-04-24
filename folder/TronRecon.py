import argparse
import os
import subprocess
import requests
import socket
import json
import threading
import datetime
from queue import Queue

# === CONFIG ===
DEFAULT_DIRSEARCH_WORDLIST_FOLDER = "/path/to/wordlist/folder"
DEFAULT_DIR_PATHS = ["admin", "login", "config", "dashboard", "logs", ".env", "backup"]
MAX_THREADS = 50

console_lock = threading.Lock()

def status(msg, symbol='+'):
    with console_lock:
        print(f"[{symbol}] {msg}")

def save_results_json(results, filename=None):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if not filename:
        filename = f"scan_report_{timestamp}.json"

    for k, v in results.get("directory_scan", {}).items():
        for scan_type in ["dirsearch_hits", "custom_paths_hits"]:
            if scan_type in v:
                sorted_hits = sorted(v[scan_type], key=lambda x: (" 200 " not in x, x))
                v[scan_type] = sorted_hits

    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    status(f"Results saved to {filename}", symbol='\u2713')

def brute_force_subdomains(domain):
    status(f"[Subdomain Scan] Starting subdomain enumeration for {domain}...")
    subdomains = set()

    tools = {
        "subfinder": f"subfinder -silent -d {domain}",
        "assetfinder": f"assetfinder --subs-only {domain}"
    }

    for name, cmd in tools.items():
        status(f"[Subdomain Scan] Running {name}...")
        try:
            result = subprocess.check_output(cmd, shell=True).decode().splitlines()
            new_results = set(filter(None, result))
            subdomains.update(new_results)
            status(f"[Subdomain Scan] {name} found {len(new_results)} subdomains.")
        except Exception as e:
            status(f"[Subdomain Scan] Failed to run {name}: {e}", symbol="!")

    status(f"[Subdomain Scan] Total unique subdomains found: {len(subdomains)}")
    return list(subdomains)

def is_alive(domain):
    for proto in ["http://", "https://"]:
        try:
            r = requests.get(proto + domain, timeout=3)
            if r.status_code < 500:
                return proto + domain
        except:
            continue
    return None

def check_alive(domains):
    status("Checking for alive domains...")
    alive = []
    def worker():
        while not q.empty():
            domain = q.get()
            live = is_alive(domain)
            if live:
                alive.append(live)
                status(f"Alive: {live}")
            q.task_done()

    q = Queue()
    for d in domains:
        q.put(d)

    for _ in range(min(MAX_THREADS, len(domains))):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

    q.join()
    return alive

def scan_ports(host, ports):
    open_ports = []
    def scanner(p):
        s = socket.socket()
        s.settimeout(0.5)
        try:
            s.connect((host, p))
            open_ports.append(p)
        except:
            pass
        s.close()

    threads = []
    for port in ports:
        t = threading.Thread(target=scanner, args=(port,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports

def run_dirsearch(url, wordlists):
    status(f"[Dirsearch] Starting directory brute-forcing for {url}...")
    try:
        output_file = f"dirsearch_result_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        for wordlist in wordlists:
            cmd = f"python3 /path/to/dirsearch/dirsearch.py -u {url} -w {wordlist} --crawl -t 50 -o {output_file}"
            subprocess.run(cmd, shell=True)
        hits = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                hits = [line.strip() for line in f if line.strip() and "/" in line]
        return hits
    except Exception as e:
        status(f"Error running Dirsearch: {e}", symbol="!")
        return []

def run_custom_path_scan(url, paths):
    found = []
    for path in paths:
        try:
            full_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
            r = requests.get(full_url, timeout=3)
            if r.status_code < 404:
                found.append(f"/{path}")
        except:
            continue
    return found

def get_custom_paths():
    return list(DEFAULT_DIR_PATHS)

def get_wordlists_from_folder(folder_path):
    wordlists = []
    if os.path.isdir(folder_path):
        for file_name in os.listdir(folder_path):
            if file_name.endswith(".txt"):
                wordlists.append(os.path.join(folder_path, file_name))
    return wordlists

def main():
    parser = argparse.ArgumentParser(description="Recon Scanner")
    parser.add_argument("-d", "--domain", required=True)
    parser.add_argument("--subenum", action="store_true")
    parser.add_argument("--subsfile", help="File of subdomains")
    parser.add_argument("-p", "--ports", default="80,443", help="Comma or 'all'")
    parser.add_argument("--json", help="Custom output file name")
    args = parser.parse_args()

    try:
        socket.gethostbyname(args.domain)
    except socket.gaierror:
        status(f"Error: Invalid domain '{args.domain}'", symbol="!")
        return

    status(f"Starting scan for: {args.domain}")
    targets = [args.domain]

    if args.subenum:
        targets += brute_force_subdomains(args.domain)
    elif args.subsfile:
        try:
            with open(args.subsfile) as f:
                targets += [line.strip() for line in f if line.strip()]
        except Exception as e:
            status(f"Failed to read subdomain file: {e}", symbol="!")

    targets = list(set(targets))
    alive_subs = check_alive(targets)

    port_results = {}
    directory_results = {}
    ports = list(range(1, 65536)) if args.ports == 'all' else list(map(int, args.ports.split(',')))
    custom_paths = get_custom_paths()
    wordlists = get_wordlists_from_folder(DEFAULT_DIRSEARCH_WORDLIST_FOLDER)

    for target in alive_subs:
        domain = target.split("//")[-1].split("/")[0]
        try:
            ip = socket.gethostbyname(domain)
        except:
            status(f"Could not resolve IP for {domain}", symbol="!")
            continue

        status(f"Scanning ports for {domain} [{ip}]...")
        open_ports = scan_ports(ip, ports)
        port_results[domain] = open_ports

        status(f"Brute-forcing directories on {target}...")
        dirsearch_hits = run_dirsearch(target, wordlists)
        custom_hits = run_custom_path_scan(target, custom_paths)
        directory_results[target] = {
            "dirsearch_hits": dirsearch_hits,
            "custom_paths_hits": custom_hits
        }

        for port in open_ports:
            url = f"http://{ip}:{port}"
            status(f"Brute-forcing directories on {url}...")
            ds_hits = run_dirsearch(url, wordlists)
            cp_hits = run_custom_path_scan(url, custom_paths)
            directory_results[url] = {
                "dirsearch_hits": ds_hits,
                "custom_paths_hits": cp_hits
            }

    scan_summary = {
        "target": args.domain,
        "subdomains": targets,
        "alive_hosts": alive_subs,
        "port_scan": port_results,
        "directory_scan": directory_results
    }

    save_results_json(scan_summary, args.json)
    status("Scan completed successfully!", symbol='\u2713')

if __name__ == "__main__":
    main()
