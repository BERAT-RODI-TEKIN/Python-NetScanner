"""
NetScanner — Visual Interface
Professional dark-theme GUI, thread-safe via queue
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import queue
import time
import sys
import os
from datetime import datetime
from typing import List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from netscanner.core.scanner import (
    NetScanner, ScanType, PortState,
    parse_targets, parse_ports, PORT_PROFILES,
    ScanResult, PortResult, VERSION, BUILD, GITHUB,
)
from netscanner.core.output import save, save_results

# ── Dark hacker theme ─────────────────────────────────────────
BG     = "#0d1117"
BG2    = "#161b22"
BG3    = "#21262d"
BORDER = "#30363d"
ACCENT = "#00d4aa"
ACC2   = "#58a6ff"
GREEN  = "#3fb950"
RED    = "#f85149"
YELLOW = "#d29922"
PURPLE = "#bc8cff"
TEXT   = "#e6edf3"
TEXT2  = "#8b949e"
MONO   = "Consolas" if sys.platform == "win32" else "Monospace"

SCAN_PROFILES = {
    "Quick scan  (top-100 T4)":       "-p top-100 -T4",
    "Intense scan (top-1000 -A T4)":  "-p top-1000 -A -T4",
    "Full port scan (1-65535 T3)":    "-p 1-65535 -T3",
    "Web services  (-p web -b)":      "-p web -b",
    "Database scan (-p db)":          "-p db",
    "Mail servers  (-p mail)":        "-p mail",
    "Remote access (-p remote)":      "-p remote",
    "Vuln check    (-p vuln -A)":     "-p vuln -A",
    "UDP scan      (-sU top-100)":    "-sU -p top-100 -T3",
    "Slow & Stealthy (-T1)":          "-p top-100 -T1",
    "Custom":                          "",
}

TIMING_MAP = {1:(3.0,50),2:(2.0,100),3:(1.0,300),4:(0.5,500),5:(0.2,800)}


def _apply_style(root: tk.Tk):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".",
                 background=BG2, foreground=TEXT,
                 fieldbackground=BG3, bordercolor=BORDER,
                 troughcolor=BG, selectbackground=ACCENT,
                 selectforeground=BG)
    s.configure("TFrame",   background=BG2)
    s.configure("TLabel",   background=BG2, foreground=TEXT)
    s.configure("TButton",  background=BG3, foreground=TEXT,
                borderwidth=1, relief="flat")
    s.map("TButton",
          background=[("active", ACCENT), ("pressed", ACC2)],
          foreground=[("active", BG)])
    s.configure("Scan.TButton", background=GREEN, foreground=BG,
                font=(MONO, 10, "bold"), padding=(14, 5))
    s.map("Scan.TButton",
          background=[("active","#2ea043"), ("disabled", BG3)])
    s.configure("Stop.TButton", background=RED, foreground=TEXT,
                font=(MONO, 10, "bold"), padding=(14, 5))
    s.map("Stop.TButton", background=[("active","#c93c37")])
    s.configure("TCombobox",
                fieldbackground=BG3, foreground=TEXT,
                background=BG3, selectbackground=ACCENT)
    s.configure("TEntry",
                fieldbackground=BG3, foreground=TEXT,
                insertcolor=ACCENT)
    s.configure("TNotebook", background=BG, tabmargins=[2,5,2,0])
    s.configure("TNotebook.Tab",
                background=BG3, foreground=TEXT2, padding=[10, 5])
    s.map("TNotebook.Tab",
          background=[("selected", BG2)],
          foreground=[("selected", ACCENT)])
    s.configure("Treeview",
                background=BG2, foreground=TEXT,
                fieldbackground=BG2, bordercolor=BORDER, rowheight=25)
    s.configure("Treeview.Heading",
                background=BG3, foreground=ACCENT,
                font=(MONO, 9, "bold"))
    s.map("Treeview",
          background=[("selected", ACCENT)],
          foreground=[("selected", BG)])
    s.configure("Horizontal.TProgressbar",
                 troughcolor=BG3, background=ACCENT, thickness=7)
    s.configure("TSeparator", background=BORDER)


class NetScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"NetScanner — {VERSION}  |  Professional Port Scanner")
        self.geometry("1300x820")
        self.minsize(950, 620)
        self.configure(bg=BG)
        _apply_style(self)

        self._results:  List[ScanResult]  = []
        self._scanner:  Optional[NetScanner] = None
        self._running   = False
        self._q: queue.Queue = queue.Queue()

        self._build_ui()
        self._poll_queue()

    # ── Build UI ─────────────────────────────────────────────
    def _build_ui(self):
        self._build_toolbar()
        self._build_body()
        self._build_statusbar()

    def _build_toolbar(self):
        bar = tk.Frame(self, bg=BG3, height=60)
        bar.pack(fill="x", side="top")
        bar.pack_propagate(False)

        tk.Label(bar, text="  ⬡ NetScanner",
                 bg=BG3, fg=ACCENT, font=(MONO, 15, "bold")
                 ).pack(side="left", padx=(10, 20))

        def lbl(t):
            tk.Label(bar, text=t, bg=BG3, fg=TEXT2,
                     font=(MONO, 10)).pack(side="left")

        def entry(var, w, fg=TEXT):
            e = tk.Entry(bar, textvariable=var, bg=BG3, fg=fg,
                         insertbackground=ACCENT, font=(MONO, 11),
                         relief="flat", width=w,
                         highlightthickness=1, highlightcolor=ACCENT,
                         highlightbackground=BORDER)
            e.pack(side="left", padx=(4, 14), ipady=5)
            return e

        lbl("Target:")
        self._tgt_var = tk.StringVar()
        e = entry(self._tgt_var, 28)
        e.bind("<Return>", lambda _: self._start_scan())

        lbl("Profile:")
        self._prof_var = tk.StringVar(value="Quick scan  (top-100 T4)")
        cb = ttk.Combobox(bar, textvariable=self._prof_var,
                          values=list(SCAN_PROFILES.keys()),
                          state="readonly", width=26)
        cb.pack(side="left", padx=(4, 14))
        cb.bind("<<ComboboxSelected>>", self._on_profile)

        lbl("Command:")
        self._cmd_var = tk.StringVar(value="-p top-100 -T4")
        entry(self._cmd_var, 32, YELLOW)

        self._scan_btn = ttk.Button(bar, text="▶  SCAN",
                                    style="Scan.TButton",
                                    command=self._start_scan)
        self._scan_btn.pack(side="left", padx=(0, 6))

        self._stop_btn = ttk.Button(bar, text="■  STOP",
                                    style="Stop.TButton",
                                    command=self._stop_scan,
                                    state="disabled")
        self._stop_btn.pack(side="left")

    def _build_body(self):
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Left: host list
        left = tk.Frame(body, bg=BG2, width=230)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        tk.Label(left, text="  SCANNED HOSTS",
                 bg=BG2, fg=ACCENT, font=(MONO, 9, "bold"),
                 pady=8, anchor="w").pack(fill="x")
        ttk.Separator(left, orient="horizontal").pack(fill="x")

        self._host_list = tk.Listbox(
            left, bg=BG2, fg=TEXT, font=(MONO, 10),
            selectbackground=ACCENT, selectforeground=BG,
            activestyle="none", bd=0, highlightthickness=0, relief="flat")
        self._host_list.pack(fill="both", expand=True, padx=4, pady=4)
        self._host_list.bind("<<ListboxSelect>>", self._on_host_select)

        # Right: notebook
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(4, 0))

        # Progress strip
        pf = tk.Frame(right, bg=BG)
        pf.pack(fill="x", pady=(4, 0))
        self._prog_var = tk.DoubleVar(value=0)
        self._prog_lbl = tk.StringVar(value="")
        ttk.Progressbar(pf, variable=self._prog_var, maximum=100,
                        mode="determinate",
                        style="Horizontal.TProgressbar"
                        ).pack(side="left", fill="x", expand=True, padx=(4, 8))
        tk.Label(pf, textvariable=self._prog_lbl,
                 bg=BG, fg=TEXT2, font=(MONO, 9), width=24
                 ).pack(side="left")

        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True, padx=4, pady=4)
        self._nb = nb

        self._tab_ports  = tk.Frame(nb, bg=BG2)
        self._tab_output = tk.Frame(nb, bg=BG)
        self._tab_info   = tk.Frame(nb, bg=BG2)
        self._tab_export = tk.Frame(nb, bg=BG2)

        nb.add(self._tab_ports,  text="  Ports  ")
        nb.add(self._tab_output, text="  Output  ")
        nb.add(self._tab_info,   text="  Host Info  ")
        nb.add(self._tab_export, text="  Export  ")

        self._build_ports_tab()
        self._build_output_tab()
        self._build_info_tab()
        self._build_export_tab()

    def _build_ports_tab(self):
        cols = ("Port","Protocol","State","Service","Version / Banner","Extra")
        self._port_tree = ttk.Treeview(
            self._tab_ports, columns=cols,
            show="headings", selectmode="browse")
        widths = (80, 80, 115, 155, 330, 180)
        for col, w in zip(cols, widths):
            self._port_tree.heading(
                col, text=col,
                command=lambda c=col: self._sort_tree(c))
            self._port_tree.column(col, width=w, anchor="w", minwidth=w)

        self._port_tree.tag_configure("open",          foreground=GREEN)
        self._port_tree.tag_configure("closed",        foreground=RED)
        self._port_tree.tag_configure("filtered",      foreground=YELLOW)
        self._port_tree.tag_configure("open|filtered", foreground=ACC2)

        vsb = ttk.Scrollbar(self._tab_ports, orient="vertical",
                            command=self._port_tree.yview)
        hsb = ttk.Scrollbar(self._tab_ports, orient="horizontal",
                            command=self._port_tree.xview)
        self._port_tree.configure(yscrollcommand=vsb.set,
                                   xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._port_tree.pack(fill="both", expand=True)

    def _build_output_tab(self):
        self._output_text = scrolledtext.ScrolledText(
            self._tab_output,
            bg="#0a0e14", fg="#a8ff78", font=(MONO, 10),
            insertbackground=ACCENT, relief="flat", bd=0,
            wrap="word", state="disabled")
        self._output_text.pack(fill="both", expand=True, padx=2, pady=2)
        self._output_text.tag_configure("hdr",  foreground=ACCENT)
        self._output_text.tag_configure("open", foreground=GREEN)
        self._output_text.tag_configure("warn", foreground=YELLOW)
        self._output_text.tag_configure("err",  foreground=RED)

    def _build_info_tab(self):
        f = tk.Frame(self._tab_info, bg=BG2)
        f.pack(padx=20, pady=20, anchor="nw")

        fields = [
            ("Target",         "_vi_target"),
            ("IP Address",     "_vi_ip"),
            ("Hostname",       "_vi_host"),
            ("Resolved From",  "_vi_resolved"),
            ("Status",         "_vi_status"),
            ("OS Hint",        "_vi_os"),
            ("TTL",            "_vi_ttl"),
            ("Open Ports",     "_vi_open"),
            ("Total Scanned",  "_vi_total"),
            ("Scan Type",      "_vi_stype"),
            ("Duration",       "_vi_dur"),
            ("Scan Time",      "_vi_time"),
        ]
        for i, (lbl, attr) in enumerate(fields):
            tk.Label(f, text=lbl+":", bg=BG2, fg=TEXT2,
                     font=(MONO, 10), anchor="e", width=18).grid(
                row=i, column=0, sticky="e", pady=4, padx=(0, 10))
            v = tk.StringVar(value="—")
            setattr(self, attr, v)
            tk.Label(f, textvariable=v, bg=BG2, fg=TEXT,
                     font=(MONO, 10, "bold"), anchor="w").grid(
                row=i, column=1, sticky="w")

    def _build_export_tab(self):
        f = tk.Frame(self._tab_export, bg=BG2)
        f.pack(padx=24, pady=24, anchor="nw")

        tk.Label(f, text="Export Results", bg=BG2, fg=ACCENT,
                 font=(MONO, 13, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 16))

        items = [
            ("Normal Text  (.txt)",   "txt",      ".txt"),
            ("JSON         (.json)",  "json",     ".json"),
            ("XML          (.xml)",   "xml",      ".xml"),
            ("Grepable     (.gnmap)", "grepable", ".gnmap"),
        ]
        for i, (lbl, fmt, ext) in enumerate(items):
            tk.Label(f, text=lbl, bg=BG2, fg=TEXT,
                     font=(MONO, 10), width=28, anchor="w").grid(
                row=i+1, column=0, sticky="w", pady=4)
            ttk.Button(f, text="Save",
                       command=lambda fm=fmt, ex=ext: self._save(fm, ex),
                       width=10).grid(row=i+1, column=1, padx=12)

        ttk.Separator(f, orient="horizontal").grid(
            row=6, column=0, columnspan=2, sticky="ew", pady=14)
        ttk.Button(f, text="💾  Save All Formats",
                   command=self._save_all, width=30).grid(
            row=7, column=0, columnspan=2, sticky="w")

    def _build_statusbar(self):
        bar = tk.Frame(self, bg=BG3, height=26)
        bar.pack(fill="x", side="bottom")
        bar.pack_propagate(False)
        self._status_var = tk.StringVar(
            value="Ready — Enter a target and press SCAN")
        tk.Label(bar, textvariable=self._status_var,
                 bg=BG3, fg=TEXT2, font=(MONO, 9), anchor="w"
                 ).pack(side="left", padx=10)
        self._time_var = tk.StringVar(value="")
        tk.Label(bar, textvariable=self._time_var,
                 bg=BG3, fg=ACCENT, font=(MONO, 9), anchor="e"
                 ).pack(side="right", padx=10)

    # ── Queue-based thread-safe UI updates ───────────────────
    def _poll_queue(self):
        try:
            while True:
                msg = self._q.get_nowait()
                k   = msg["k"]
                if k == "prog":
                    d, t = msg["d"], msg["t"]
                    self._prog_var.set(d / t * 100 if t else 0)
                    self._prog_lbl.set(f"{d}/{t} ports")
                elif k == "open":
                    pr: PortResult = msg["pr"]
                    self._append_output(
                        f"  {pr.port:<7}/{pr.protocol:<5}  OPEN  "
                        f"{pr.service:<22}  "
                        f"{pr.version or pr.banner or ''}\n",
                        "open")
                    self._port_tree.insert(
                        "", "end",
                        values=(pr.port, pr.protocol, "open",
                                pr.service,
                                pr.version or pr.banner or "",
                                pr.extra or ""),
                        tags=("open",))
                    self._port_tree.yview_moveto(1.0)
                elif k == "start":
                    self._status_var.set(f"Scanning: {msg['tgt']}")
                    self._append_output(
                        f"\n{'─'*65}\n"
                        f"  Target: {msg['tgt']}  │  "
                        f"{datetime.now().strftime('%H:%M:%S')}\n"
                        f"{'─'*65}\n", "hdr")
                    self._nb.select(1)
                elif k == "done":
                    self._on_result(msg["r"])
                elif k == "all_done":
                    self._scan_done()
        except queue.Empty:
            pass
        self.after(40, self._poll_queue)

    # ── Callbacks ────────────────────────────────────────────
    def _on_profile(self, _=None):
        p = self._prof_var.get()
        if p != "Custom":
            self._cmd_var.set(SCAN_PROFILES.get(p, ""))

    def _on_host_select(self, _=None):
        sel = self._host_list.curselection()
        if sel and sel[0] < len(self._results):
            self._display_result(self._results[sel[0]])

    # ── Scan control ─────────────────────────────────────────
    def _parse_cmd(self):
        cmd = self._cmd_var.get().strip()
        kw = dict(scan_type=ScanType.TCP_CONNECT,
                  timeout=1.0, threads=300,
                  do_banner=True, skip_ping=False,
                  os_detect=False, show_closed=False,
                  ports=parse_ports("top-100"))
        tokens = cmd.split()
        i = 0
        while i < len(tokens):
            t = tokens[i]
            if t == "-sU":
                kw["scan_type"] = ScanType.UDP
            elif t in ("-b", "--banner"):
                kw["do_banner"] = True
            elif t in ("-O", "--os"):
                kw["os_detect"] = True
            elif t in ("-A", "--aggressive"):
                kw["do_banner"] = True
                kw["os_detect"] = True
            elif t == "-Pn":
                kw["skip_ping"] = True
            elif t == "--closed":
                kw["show_closed"] = True
            elif len(t) == 3 and t.startswith("-T") and t[2].isdigit():
                to, th = TIMING_MAP.get(int(t[2]), (1.0, 300))
                kw["timeout"] = to
                kw["threads"] = th
            elif t in ("-p", "--ports") and i+1 < len(tokens):
                i += 1
                kw["ports"] = parse_ports(tokens[i])
            i += 1
        return kw

    def _start_scan(self):
        target = self._tgt_var.get().strip()
        if not target:
            messagebox.showwarning("No Target",
                "Please enter a target host or IP.\nExample: 192.168.1.1")
            return
        if self._running:
            return

        self._results.clear()
        self._host_list.delete(0, "end")
        self._port_tree.delete(*self._port_tree.get_children())
        self._clear_output()
        self._prog_var.set(0)
        self._prog_lbl.set("")
        self._running = True
        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")

        kw      = self._parse_cmd()
        targets = parse_targets(target)
        self._status_var.set(
            f"Scanning {len(targets)} host(s), {len(kw['ports'])} ports ...")

        def worker():
            sc = NetScanner(
                scan_type   = kw["scan_type"],
                timeout     = kw["timeout"],
                threads     = kw["threads"],
                do_banner   = kw["do_banner"],
                skip_ping   = kw["skip_ping"],
                os_detect   = kw["os_detect"],
                show_closed = kw["show_closed"],
                progress_cb = lambda d, t: self._q.put(
                    {"k":"prog","d":d,"t":t}),
                found_cb    = lambda pr: self._q.put(
                    {"k":"open","pr":pr}),
            )
            self._scanner = sc
            for tgt in targets:
                if not self._running:
                    break
                self._q.put({"k":"start","tgt":tgt})
                r = sc.scan(tgt, kw["ports"])
                self._q.put({"k":"done","r":r})
            self._q.put({"k":"all_done"})

        threading.Thread(target=worker, daemon=True).start()

    def _stop_scan(self):
        if self._scanner:
            self._scanner.stop()
        self._running = False
        self._status_var.set("Scan stopped by user.")
        self._scan_done()

    def _scan_done(self):
        self._running = False
        self._scan_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._prog_var.set(100)
        total_open = sum(len(r.open_ports) for r in self._results)
        self._status_var.set(
            f"Done — {total_open} open port(s) across "
            f"{len(self._results)} host(s)")
        self._time_var.set(datetime.now().strftime("%H:%M:%S"))

    def _on_result(self, result: ScanResult):
        self._results.append(result)
        oc    = len(result.open_ports)
        label = f"  {result.target}"
        if result.ip and result.ip != result.target:
            label += f"  ({result.ip})"
        label += f"\n  [{oc} open]"
        self._host_list.insert("end", label)
        self._host_list.selection_clear(0, "end")
        self._host_list.selection_set("end")
        self._host_list.see("end")
        self._display_result(result)
        self._nb.select(0)

    def _display_result(self, result: ScanResult):
        self._port_tree.delete(*self._port_tree.get_children())
        for pr in result.ports:
            self._port_tree.insert(
                "", "end",
                values=(pr.port, pr.protocol, pr.state.value,
                        pr.service,
                        pr.version or pr.banner or "",
                        pr.extra or ""),
                tags=(pr.state.value,))

        self._vi_target.set(result.target)
        self._vi_ip.set(result.ip or "—")
        self._vi_host.set(result.hostname or "—")
        self._vi_resolved.set(result.resolved_from or "—")
        self._vi_status.set("UP ✓" if result.is_up else "DOWN ✗")
        self._vi_os.set(result.os_hint or "—")
        self._vi_ttl.set(str(result.ttl) if result.ttl else "—")
        self._vi_open.set(str(len(result.open_ports)))
        self._vi_total.set(str(result.total_scanned))
        self._vi_stype.set(result.scan_type.value)
        self._vi_dur.set(f"{result.duration}s")
        self._vi_time.set(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    def _clear_output(self):
        self._output_text.configure(state="normal")
        self._output_text.delete("1.0", "end")
        self._output_text.configure(state="disabled")

    def _append_output(self, text: str, tag: str = ""):
        self._output_text.configure(state="normal")
        self._output_text.insert("end", text, tag)
        self._output_text.see("end")
        self._output_text.configure(state="disabled")

    def _sort_tree(self, col: str):
        rows = [(self._port_tree.set(k, col), k)
                for k in self._port_tree.get_children("")]
        try:    rows.sort(key=lambda x: int(x[0]))
        except: rows.sort()
        for i, (_, k) in enumerate(rows):
            self._port_tree.move(k, "", i)

    def _save(self, fmt: str, ext: str):
        if not self._results:
            messagebox.showinfo("No Results", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=[(fmt.upper(), f"*{ext}"), ("All", "*.*")])
        if path:
            save(self._results, path, fmt)
            self._status_var.set(f"Saved → {path}")

    def _save_all(self):
        if not self._results:
            messagebox.showinfo("No Results", "Run a scan first.")
            return
        base = filedialog.asksaveasfilename(
            title="Choose base filename (no extension)",
            filetypes=[("All", "*.*")])
        if base:
            for fmt, ext in [("txt","txt"),("json","json"),
                              ("xml","xml"),("grepable","gnmap")]:
                save(self._results, f"{base}.{ext}", fmt)
            self._status_var.set(f"All formats saved → {base}.*")


def launch_gui():
    app = NetScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()
