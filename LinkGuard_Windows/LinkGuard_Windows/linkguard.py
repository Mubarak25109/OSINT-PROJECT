#!/usr/bin/env python3
"""
LinkGuard OSINT - simple, passive website information checker.
Uses only Python's standard library. Only make checks against URLs you are
authorized to inspect. This tool does not determine whether a site is safe.
"""
import ipaddress
import socket
import ssl
import time
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

APP_TITLE = "LinkGuard OSINT"
TIMEOUT = 8
USER_AGENT = "LinkGuardOSINT/1.0 (educational passive checker)"


def normalize_url(raw):
    raw = raw.strip()
    if not raw:
        raise ValueError("Enter a website URL.")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a valid domain.")
    try:
        parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")
    # Avoid embedded credentials and local/non-web schemes.
    if parsed.username or parsed.password:
        raise ValueError("Do not include usernames or passwords in the URL.")
    host = parsed.hostname.encode("idna").decode("ascii")
    netloc = host
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path or "/", parsed.params,
                       parsed.query, "")), host


def resolve_ip(host):
    try:
        # Literal IPs are accepted without DNS lookup.
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        ips = sorted({item[4][0] for item in records})
        return ", ".join(ips) if ips else "No address returned"
    except socket.gaierror as exc:
        return f"DNS lookup failed: {exc}"


def request_url(url):
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    start = time.perf_counter()
    try:
        with urlopen(req, timeout=TIMEOUT) as response:
            elapsed = time.perf_counter() - start
            return {
                "status": getattr(response, "status", response.getcode()),
                "final_url": response.geturl(),
                "elapsed": elapsed,
                "error": None,
            }
    except HTTPError as exc:
        elapsed = time.perf_counter() - start
        return {"status": exc.code, "final_url": exc.geturl(),
                "elapsed": elapsed, "error": f"HTTP error: {exc.code}"}
    except Exception as exc:
        elapsed = time.perf_counter() - start
        return {"status": "Unavailable", "final_url": url,
                "elapsed": elapsed, "error": str(exc)}


def check_robots(origin):
    robots_url = origin.rstrip("/") + "/robots.txt"
    req = Request(robots_url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(req, timeout=TIMEOUT) as response:
            data = response.read(2048).decode("utf-8", errors="replace")
            return ("Found", data[:500].strip() or "(File is empty)")
    except HTTPError as exc:
        if exc.code == 404:
            return ("Not found (404)", "")
        return (f"HTTP {exc.code}", "")
    except Exception as exc:
        return (f"Unavailable: {exc}", "")


def check_tls(host, port):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                version = tls_sock.version() or "Unknown"
                subject = cert.get("subject", ())
                common_name = ""
                for group in subject:
                    for key, value in group:
                        if key == "commonName":
                            common_name = value
                return f"Valid certificate; protocol {version}" + (
                    f"; issued to {common_name}" if common_name else "")
    except Exception as exc:
        return f"Could not verify TLS: {exc}"


def inspect(raw):
    url, host = normalize_url(raw)
    parsed = urlparse(url)
    ip_result = resolve_ip(host)
    web_result = request_url(url)
    robots_status, robots_text = check_robots(
        f"{parsed.scheme}://{parsed.netloc}")
    if parsed.scheme == "https":
        tls_result = check_tls(host, parsed.port or 443)
    else:
        tls_result = "Not checked (website URL uses HTTP, not HTTPS)"
    return {
        "input": raw.strip(),
        "domain": host,
        "ip": ip_result,
        "https": "Enabled" if parsed.scheme == "https" else "Not enabled",
        "status": web_result["status"],
        "final_url": web_result["final_url"],
        "time": f'{web_result["elapsed"]:.2f} seconds',
        "website_error": web_result["error"] or "None",
        "robots": robots_status,
        "robots_text": robots_text,
        "tls": tls_result,
    }


class LinkGuardApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("780x690")
        root.minsize(640, 560)
        root.configure(bg="#0b1020")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#0b1020")
        style.configure("TLabel", background="#0b1020", foreground="#e8eefc",
                        font=("Arial", 10))
        style.configure("Title.TLabel", font=("Arial", 23, "bold"),
                        foreground="#66d9ef")
        style.configure("Sub.TLabel", foreground="#9eacc8")
        style.configure("TButton", font=("Arial", 10, "bold"), padding=9)
        style.configure("TEntry", padding=9)

        outer = ttk.Frame(root, padding=22)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="LINKGUARD", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text="OSINT  •  Passive Website Information Checker",
                  style="Sub.TLabel").pack(anchor="w", pady=(2, 18))

        ttk.Label(outer, text="Website URL").pack(anchor="w")
        input_row = ttk.Frame(outer)
        input_row.pack(fill="x", pady=(6, 12))
        self.url_var = tk.StringVar()
        self.entry = ttk.Entry(input_row, textvariable=self.url_var)
        self.entry.pack(side="left", fill="x", expand=True)
        self.entry.bind("<Return>", lambda _event: self.run_check())
        self.check_button = ttk.Button(input_row, text="Inspect Website",
                                       command=self.run_check)
        self.check_button.pack(side="left", padx=(8, 0))

        self.status_var = tk.StringVar(value="Ready. Enter a website to begin.")
        ttk.Label(outer, textvariable=self.status_var, style="Sub.TLabel").pack(
            anchor="w", pady=(0, 8))

        report_frame = ttk.Frame(outer)
        report_frame.pack(fill="both", expand=True)
        self.output = tk.Text(
            report_frame, wrap="word", bg="#111a2e", fg="#e8eefc",
            insertbackground="white", relief="flat", padx=15, pady=14,
            font=("Consolas", 10), height=22
        )
        scroll = ttk.Scrollbar(report_frame, command=self.output.yview)
        self.output.configure(yscrollcommand=scroll.set)
        self.output.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.output.insert("1.0",
            "LINKGUARD REPORT\n"
            "────────────────────────────────────────────\n\n"
            "Your report will appear here.\n\n"
            "Note: Technical information is not a safety guarantee.\n")
        self.output.configure(state="disabled")

        bottom = ttk.Frame(outer)
        bottom.pack(fill="x", pady=(12, 0))
        ttk.Button(bottom, text="Clear", command=self.clear).pack(side="left")
        ttk.Button(bottom, text="Copy Report", command=self.copy_report).pack(
            side="left", padx=8)
        ttk.Label(bottom, text="Educational use • Python 3",
                  style="Sub.TLabel").pack(side="right")

    def set_report(self, content):
        self.output.configure(state="normal")
        self.output.delete("1.0", "end")
        self.output.insert("1.0", content)
        self.output.configure(state="disabled")

    def run_check(self):
        raw = self.url_var.get()
        self.check_button.configure(state="disabled")
        self.status_var.set("Inspecting public website information…")
        self.root.update_idletasks()
        try:
            data = inspect(raw)
            report = (
                "LINKGUARD OSINT REPORT\n"
                "════════════════════════════════════════════\n\n"
                f"Input URL       : {data['input']}\n"
                f"Domain          : {data['domain']}\n"
                f"IP Address(es)  : {data['ip']}\n"
                f"HTTPS           : {data['https']}\n"
                f"HTTP Status     : {data['status']}\n"
                f"Response Time   : {data['time']}\n"
                f"robots.txt      : {data['robots']}\n"
                f"TLS             : {data['tls']}\n"
                f"Final URL       : {data['final_url']}\n"
                f"Request Note    : {data['website_error']}\n\n"
                "ROBOTS.TXT PREVIEW\n"
                "────────────────────────────────────────────\n"
                f"{data['robots_text'] or '(No preview available)'}\n\n"
                "IMPORTANT\n"
                "────────────────────────────────────────────\n"
                "This report contains basic technical observations only.\n"
                "It does NOT prove that a website is safe or trustworthy.\n"
                "robots.txt is public guidance for crawlers, not a security control.\n"
            )
            self.set_report(report)
            self.status_var.set("Inspection complete.")
        except ValueError as exc:
            messagebox.showerror("Invalid URL", str(exc))
            self.status_var.set("Please correct the URL and try again.")
        except Exception as exc:
            messagebox.showerror("Inspection error", str(exc))
            self.status_var.set("Inspection could not be completed.")
        finally:
            self.check_button.configure(state="normal")

    def clear(self):
        self.url_var.set("")
        self.set_report("LINKGUARD REPORT\n\nYour report will appear here.\n")
        self.status_var.set("Ready.")

    def copy_report(self):
        content = self.output.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        self.status_var.set("Report copied to clipboard.")


def main():
    root = tk.Tk()
    LinkGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
