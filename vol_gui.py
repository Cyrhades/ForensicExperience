import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import threading
import os
import re
import json
import configparser
import requests
import struct
from collections import Counter

# --- MD4 Implementation (for NTLM) ---
def md4_compress(state, block):
    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z
    
    def rot(val, n): return ((val << n) & 0xffffffff) | (val >> (32 - n))
    
    x = struct.unpack("<16I", block)
    a, b, c, d = state
    
    # Round 1
    s1 = [3, 7, 11, 19]
    for i in range(16):
        r = i % 4
        if r == 0: a = rot((a + F(b, c, d) + x[i]) & 0xffffffff, s1[r])
        elif r == 1: d = rot((d + F(a, b, c) + x[i]) & 0xffffffff, s1[r])
        elif r == 2: c = rot((c + F(d, a, b) + x[i]) & 0xffffffff, s1[r])
        elif r == 3: b = rot((b + F(c, d, a) + x[i]) & 0xffffffff, s1[r])

    # Round 2
    s2 = [3, 5, 9, 13]
    idx2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
    for i in range(16):
        r = i % 4
        k = idx2[i]
        if r == 0: a = rot((a + G(b, c, d) + x[k] + 0x5a827999) & 0xffffffff, s2[r])
        elif r == 1: d = rot((d + G(a, b, c) + x[k] + 0x5a827999) & 0xffffffff, s2[r])
        elif r == 2: c = rot((c + G(d, a, b) + x[k] + 0x5a827999) & 0xffffffff, s2[r])
        elif r == 3: b = rot((b + G(c, d, a) + x[k] + 0x5a827999) & 0xffffffff, s2[r])
        
    # Round 3
    s3 = [3, 9, 11, 15]
    idx3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
    for i in range(16):
        r = i % 4
        k = idx3[i]
        if r == 0: a = rot((a + H(b, c, d) + x[k] + 0x6ed9eba1) & 0xffffffff, s3[r])
        elif r == 1: d = rot((d + H(a, b, c) + x[k] + 0x6ed9eba1) & 0xffffffff, s3[r])
        elif r == 2: c = rot((c + H(d, a, b) + x[k] + 0x6ed9eba1) & 0xffffffff, s3[r])
        elif r == 3: b = rot((b + H(c, d, a) + x[k] + 0x6ed9eba1) & 0xffffffff, s3[r])

    return [(state[0]+a)&0xffffffff, (state[1]+b)&0xffffffff, (state[2]+c)&0xffffffff, (state[3]+d)&0xffffffff]

def ntlm_hash(password):
    # Unicode (UTF-16LE) encoding
    data = password.encode('utf-16le')
    
    # Padding
    bit_len = len(data) * 8
    data += b'\x80'
    while (len(data) + 8) % 64 != 0: data += b'\x00'
    data += struct.pack("<Q", bit_len)
    
    # MD4 processing
    state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    for i in range(0, len(data), 64):
        state = md4_compress(state, data[i:i+64])
        
    return struct.pack("<4I", *state).hex()

class ForensicExperienceApp:
    def __init__(self, root):
        self.root = root
        self.config = configparser.ConfigParser()
        self.load_config()
        self.load_locales()
        
        self.root.title(self.tr("app_title"))
        self.root.geometry("1600x800")
        
        # Professional Palette
        self.colors = {
            "bg": "#F4F7F9",
            "bg_pane": "#FFFFFF",
            "header": "#1A2A3A",
            "accent": "#3498DB",
            "accent_dark": "#2980B9",
            "text": "#2C3E50",
            "text_dim": "#7F8C8D",
            "border": "#DCDFE3",
            "success": "#27AE60",
            "danger": "#E74C3C",
            "console_bg": "#121212", 
            "console_fg": "#E0E0E0"
        }
        
        self.root.configure(bg=self.colors["bg"])
        
        self.bin_dir = os.path.join(os.getcwd(), "bin")
        self.available_vols = self.detect_binaries()
        
        # Use config for default vol if available
        saved_vol = self.config.get("General", "vol_binary", fallback="")
        self.vol_path = os.path.join(self.bin_dir, saved_vol) if saved_vol in [os.path.basename(v) for v in self.available_vols] else (self.available_vols[0] if self.available_vols else "")
        
        self.current_dump = None
        self.detected_profile = None
        self.hives = {}
        
        self.lang_var = tk.StringVar(value=self.config.get("General", "language", fallback="en"))
        self.active_tasks = 0
        
        # AI Configuration
        self.ai_enabled = self.config.getboolean("AI", "enabled", fallback=False)
        self.ai_model = self.config.get("AI", "model", fallback="llama3")
        self.ai_url = self.config.get("AI", "url", fallback="http://localhost:11434/api/generate")
        self.ai_timeout = self.config.getint("AI", "timeout", fallback=60)
        
        self.wordlist_path = ""
        self.hashes_found = [] # (user, ntlm) pairs
        self.stop_cracking = threading.Event()
        
        self.setup_styles()
        self.setup_ui()

    def load_config(self):
        if not os.path.exists("config.ini"):
            self.config["General"] = {"language": "en", "vol_binary": "vol2.exe"}
            with open("config.ini", "w") as f: self.config.write(f)
        else:
            self.config.read("config.ini")

    def load_locales(self):
        lang = self.config.get("General", "language", fallback="en")
        locale_path = f"locales/{lang}.json"
        if os.path.exists(locale_path):
            with open(locale_path, "r", encoding="utf-8") as f:
                self.locales = json.load(f)
        else:
            self.locales = {}

    def tr(self, key): 
        return self.locales.get(key, key)

    def detect_binaries(self):
        vols = []
        if os.path.exists(self.bin_dir):
            for f in os.listdir(self.bin_dir):
                if f.startswith("vol") and f.endswith(".exe"):
                    vols.append(os.path.join(self.bin_dir, f))
        return sorted(vols) if vols else []

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("TNotebook", background=self.colors["bg"], borderwidth=0)
        style.configure("TNotebook.Tab", background=self.colors["border"], foreground=self.colors["text_dim"], 
                        padding=[20, 10], font=("Segoe UI", 9, "bold"), borderwidth=0, shiftrelief=0)
        
        style.map("TNotebook.Tab", 
                  background=[("selected", self.colors["bg_pane"]), ("active", self.colors["border"])],
                  foreground=[("selected", self.colors["accent"]), ("active", self.colors["text"])],
                  padding=[("selected", [20, 10]), ("active", [20, 10])],
                  font=[("selected", ("Segoe UI", 9, "bold")), ("active", ("Segoe UI", 9, "bold"))])
        
        style.map("Treeview", background=[("selected", self.colors["accent"])], foreground=[("selected", "white")])
        style.configure("Treeview", background=self.colors["bg_pane"], foreground=self.colors["text"], 
                        fieldbackground=self.colors["bg_pane"], font=("Segoe UI", 9), rowheight=30, borderwidth=0)
        style.configure("Treeview.Heading", background=self.colors["bg"], foreground=self.colors["header"], 
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=5)
        
        style.configure("Vertical.TScrollbar", background=self.colors["bg"], troughcolor=self.colors["bg"], 
                        bordercolor=self.colors["border"], arrowcolor=self.colors["text_dim"])

    def setup_ui(self):
        # Header
        header = tk.Frame(self.root, bg=self.colors["header"], height=80)
        header.pack(fill="x")
        
        title_frame = tk.Frame(header, bg=self.colors["header"])
        title_frame.pack(side="left", padx=30)
        tk.Label(title_frame, text="Forensic", font=("Segoe UI", 20, "bold"), fg="white", bg=self.colors["header"]).pack(side="left")
        tk.Label(title_frame, text="Experience", font=("Segoe UI", 20, "bold"), fg=self.colors["accent"], bg=self.colors["header"]).pack(side="left")
        # Top Actions
        actions_frame = tk.Frame(header, bg=self.colors["header"])
        actions_frame.pack(side="right", padx=30)
        
        self.load_btn = tk.Button(actions_frame, text=self.tr("import_btn"), command=self.load_dump, 
                                  bg=self.colors["accent"], fg="white", font=("Segoe UI", 9, "bold"),
                                  relief="flat", padx=25, pady=10, cursor="hand2",
                                  activebackground=self.colors["accent_dark"])
        self.load_btn.pack(side="right", padx=(20, 0))
        
        self.file_status = tk.Label(actions_frame, text=self.tr("ready_status"), fg=self.colors["text_dim"], bg=self.colors["header"], font=("Segoe UI", 9))
        self.file_status.pack(side="right", padx=10)

        # Main Workspace
        self.workspace = tk.Frame(self.root, bg=self.colors["bg"], padx=10, pady=10)
        self.workspace.pack(fill="both", expand=True)

        # Container for Notebook and Config Button
        self.nb_container = tk.Frame(self.workspace, bg=self.colors["bg"])
        self.nb_container.pack(fill="x", side="top")

        self.config_btn = tk.Button(self.nb_container, text=" ⚙ " + self.tr("tab_config"), 
                                    command=self.open_config_window,
                                    bg=self.colors["accent"], fg="white", font=("Segoe UI", 9, "bold"),
                                    relief="flat", padx=15, pady=8, cursor="hand2")
        self.config_btn.pack(side="right", pady=(0, 5))

        self.ai_toggle_btn = tk.Button(self.nb_container, text=" 🤖 " + self.tr("tab_ai"), 
                                       command=self.toggle_ai_panel,
                                       bg=self.colors["success"], fg="white", font=("Segoe UI", 9, "bold"),
                                       relief="flat", padx=15, pady=8, cursor="hand2")
        self.ai_toggle_btn.pack(side="right", padx=10, pady=(0, 5))

        # Main Workspace Split
        self.main_split = tk.Frame(self.workspace, bg=self.colors["bg"])
        self.main_split.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(self.main_split)
        self.notebook.pack(side="left", fill="both", expand=True)
        
        # AI Side Panel
        self.ai_panel = tk.Frame(self.main_split, bg=self.colors["bg_pane"], width=450, bd=1, relief="solid")
        # Initially hidden or shown based on config? Let's show it if enabled.
        if self.ai_enabled:
            self.ai_panel.pack(side="right", fill="y", padx=(10, 0))
        self.ai_visible = self.ai_enabled
        self.setup_ai_panel()

        # Tabs
        self.tab_dash = tk.Frame(self.notebook, bg=self.colors["bg_pane"])
        self.notebook.add(self.tab_dash, text=self.tr("tab_dashboard"))
        self.setup_dashboard()
        
        self.tab_proc = tk.Frame(self.notebook, bg=self.colors["bg_pane"])
        self.notebook.add(self.tab_proc, text=self.tr("tab_processes"))
        self.setup_processes()


        self.tab_files = tk.Frame(self.notebook, bg=self.colors["bg_pane"])
        self.notebook.add(self.tab_files, text=self.tr("tab_files"))
        self.setup_files_tab()

        self.tab_env = tk.Frame(self.notebook, bg=self.colors["bg_pane"])
        self.notebook.add(self.tab_env, text=self.tr("tab_envars"))
        self.setup_envars_tab()
        
        self.tab_sec = tk.Frame(self.notebook, bg=self.colors["bg_pane"])
        self.notebook.add(self.tab_sec, text=self.tr("tab_security"))
        self.setup_security()

        # Footer
        footer = tk.Frame(self.root, bg=self.colors["bg_pane"], height=35)
        footer.pack(fill="x", side="bottom")
        tk.Frame(footer, bg=self.colors["border"], height=1).pack(fill="x")
        self.status_bar = tk.Label(footer, text=" " + self.tr("ready_status"), bg=self.colors["bg_pane"], fg=self.colors["text_dim"], font=("Segoe UI", 8), padx=10)
        self.status_bar.pack(side="left", pady=5)
        
        self.task_label = tk.Label(footer, text="", bg=self.colors["bg_pane"], fg=self.colors["accent"], font=("Segoe UI", 8, "bold"), padx=10)
        self.task_label.pack(side="right", pady=5)
        
        self.progress = ttk.Progressbar(footer, mode="indeterminate", length=250)
        self.progress.pack(side="right", padx=10, pady=5)

    def on_vol_change(self, event=None):
        selection = self.vol_selector_conf.get() if hasattr(self, 'vol_selector_conf') else (event.widget.get() if event else None)
        if selection:
            self.vol_path = os.path.join(self.bin_dir, selection)
            self.update_status(f"Switched to {selection}")
            self.detected_profile = None
            self.meta_vars["vol_profile"].set("Detection Required")

    def open_config_window(self):
        conf_win = tk.Toplevel(self.root)
        conf_win.title(self.tr("config_title"))
        conf_win.geometry("550x550")
        conf_win.configure(bg=self.colors["bg"])
        conf_win.transient(self.root)
        conf_win.grab_set()

        # Modern Header
        header = tk.Frame(conf_win, bg=self.colors["header"], pady=20)
        header.pack(fill="x")
        tk.Label(header, text=" ⚙  " + self.tr("config_title"), font=("Segoe UI", 12, "bold"), 
                 bg=self.colors["header"], fg="white").pack(padx=30, anchor="w")

        main_container = tk.ScrollableFrame(conf_win) if hasattr(tk, "ScrollableFrame") else tk.Frame(conf_win, bg=self.colors["bg"], padx=25, pady=20)
        main_container.pack(fill="both", expand=True)

        # --- Section: General Settings ---
        section_gen = tk.LabelFrame(main_container, text=" " + self.tr("tab_dashboard").strip() + " ", font=("Segoe UI", 9, "bold"),
                                   bg=self.colors["bg_pane"], fg=self.colors["accent"], bd=1, relief="solid", padx=15, pady=15)
        section_gen.pack(fill="x", pady=(0, 20))

        # Row: Language
        row_lang = tk.Frame(section_gen, bg=self.colors["bg_pane"], pady=8)
        row_lang.pack(fill="x")
        tk.Label(row_lang, text=self.tr("config_lang"), font=("Segoe UI", 9), fg=self.colors["text"], bg=self.colors["bg_pane"], width=18, anchor="w").pack(side="left")
        self.lang_cb = ttk.Combobox(row_lang, textvariable=self.lang_var, values=["en", "fr"], state="readonly", width=12)
        self.lang_cb.pack(side="left")

        # Row: Volatility Binary
        row_vol = tk.Frame(section_gen, bg=self.colors["bg_pane"], pady=8)
        row_vol.pack(fill="x")
        tk.Label(row_vol, text=self.tr("vol_binary_label"), font=("Segoe UI", 9), fg=self.colors["text"], bg=self.colors["bg_pane"], width=18, anchor="w").pack(side="left")
        self.vol_selector_conf = ttk.Combobox(row_vol, values=[os.path.basename(v) for v in self.available_vols], state="readonly", width=18)
        if self.available_vols:
            self.vol_selector_conf.set(os.path.basename(self.vol_path))
        self.vol_selector_conf.pack(side="left")

        # --- Section: AI Assistant ---
        section_ai = tk.LabelFrame(main_container, text=" " + self.tr("tab_ai").strip() + " ", font=("Segoe UI", 9, "bold"),
                                  bg=self.colors["bg_pane"], fg=self.colors["accent"], bd=1, relief="solid", padx=15, pady=15)
        section_ai.pack(fill="x")

        # Row: Enable AI
        row_ai_enable = tk.Frame(section_ai, bg=self.colors["bg_pane"], pady=5)
        row_ai_enable.pack(fill="x")
        self.ai_enabled_var = tk.BooleanVar(value=self.ai_enabled)
        tk.Checkbutton(row_ai_enable, text=self.tr("ai_enable_label"), variable=self.ai_enabled_var, 
                       bg=self.colors["bg_pane"], activebackground=self.colors["bg_pane"],
                       font=("Segoe UI", 9, "bold"), fg=self.colors["text"]).pack(side="left")

        # Row: AI Model
        row_ai_model = tk.Frame(section_ai, bg=self.colors["bg_pane"], pady=8)
        row_ai_model.pack(fill="x")
        tk.Label(row_ai_model, text=self.tr("ai_model_label"), font=("Segoe UI", 9), bg=self.colors["bg_pane"], fg=self.colors["text"], width=18, anchor="w").pack(side="left")
        self.ai_model_entry = ttk.Combobox(row_ai_model, values=["llama3", "mistral", "phi3", "gemma"], width=15)
        self.ai_model_entry.set(self.ai_model)
        self.ai_model_entry.pack(side="left")

        # Row: AI URL
        row_ai_url = tk.Frame(section_ai, bg=self.colors["bg_pane"], pady=8)
        row_ai_url.pack(fill="x")
        tk.Label(row_ai_url, text=self.tr("ai_url_label"), font=("Segoe UI", 9), bg=self.colors["bg_pane"], fg=self.colors["text"], width=18, anchor="w").pack(side="left")
        self.ai_url_entry = tk.Entry(row_ai_url, font=("Segoe UI", 9), relief="solid", bd=1)
        self.ai_url_entry.insert(0, self.ai_url)
        self.ai_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # Row: AI Timeout
        row_ai_timeout = tk.Frame(section_ai, bg=self.colors["bg_pane"], pady=8)
        row_ai_timeout.pack(fill="x")
        tk.Label(row_ai_timeout, text=self.tr("ai_timeout_label"), font=("Segoe UI", 9), bg=self.colors["bg_pane"], fg=self.colors["text"], width=18, anchor="w").pack(side="left")
        self.ai_timeout_entry = tk.Entry(row_ai_timeout, font=("Segoe UI", 9), relief="solid", bd=1, width=10)
        self.ai_timeout_entry.insert(0, str(self.ai_timeout))
        self.ai_timeout_entry.pack(side="left")

        # Footer Actions
        footer = tk.Frame(conf_win, bg=self.colors["bg"], padx=25, pady=20)
        footer.pack(fill="x", side="bottom")
        
        btn_save = tk.Button(footer, text="  💾  " + self.tr("config_save") + "  ", 
                             command=lambda: self.save_app_config(conf_win), 
                             bg=self.colors["accent"], fg="white", font=("Segoe UI", 10, "bold"),
                             relief="flat", padx=30, pady=12, cursor="hand2")
        btn_save.pack(side="right")
        
        btn_cancel = tk.Button(footer, text=self.tr("copy_pid").replace("Copy PID", "Cancel"), # Placeholder for cancel if needed or just use X
                               command=conf_win.destroy, bg=self.colors["bg"], fg=self.colors["text_dim"], 
                               relief="flat", font=("Segoe UI", 9), padx=20, cursor="hand2")
        # btn_cancel.pack(side="right", padx=10) # Optional cancel button

    def save_app_config(self, window):
        self.config.set("General", "language", self.lang_var.get())
        if self.vol_selector_conf.get():
            selection = self.vol_selector_conf.get()
            self.config.set("General", "vol_binary", selection)
            self.vol_path = os.path.join(self.bin_dir, selection)
            self.update_status(f"Switched to {selection}")
        
        # Save AI Settings
        self.ai_enabled = self.ai_enabled_var.get()
        self.ai_model = self.ai_model_entry.get()
        self.ai_url = self.ai_url_entry.get()
        try:
            self.ai_timeout = int(self.ai_timeout_entry.get())
        except:
            self.ai_timeout = 60
        
        if not self.config.has_section("AI"): self.config.add_section("AI")
        self.config.set("AI", "enabled", str(self.ai_enabled))
        self.config.set("AI", "model", self.ai_model)
        self.config.set("AI", "url", self.ai_url)
        self.config.set("AI", "timeout", str(self.ai_timeout))

        with open("config.ini", "w") as f:
            self.config.write(f)
        
        messagebox.showinfo("Config", self.tr("config_saved_msg"))
        window.destroy()

    def setup_dashboard(self):
        container = tk.Frame(self.tab_dash, bg=self.colors["bg_pane"], padx=40, pady=40)
        container.pack(fill="both", expand=True)
        tk.Label(container, text=self.tr("target_overview"), font=("Segoe UI", 14, "bold"), bg=self.colors["bg_pane"], fg=self.colors["header"]).pack(anchor="w", pady=(0, 25))
        
        # Internal stable keys for logic
        self.meta_vars = {
            "vol_profile": tk.StringVar(value="..."),
            "computer_name": tk.StringVar(value="..."),
            "primary_user": tk.StringVar(value="..."),
            "sys_arch": tk.StringVar(value="..."),
            "sys_time": tk.StringVar(value="..."),
            "num_cpus": tk.StringVar(value="..."),
            "service_pack": tk.StringVar(value="..."),
            "kdbg_addr": tk.StringVar(value="..."),
            "dump_loc": tk.StringVar(value="...")
        }
        
        # Display Mapping (Key -> Localization Key)
        display_map = [
            ("vol_profile", "vol_profile"),
            ("computer_name", "computer_name"),
            ("primary_user", "primary_user"),
            ("sys_arch", "sys_arch"),
            ("sys_time", "sys_time"),
            ("num_cpus", "num_cpus"),
            ("service_pack", "service_pack"),
            ("kdbg_addr", "kdbg_addr"),
            ("dump_loc", "dump_loc")
        ]

        for key, loc_key in display_map:
            var = self.meta_vars[key]
            row = tk.Frame(container, bg=self.colors["bg_pane"], pady=8)
            row.pack(fill="x")
            label_text = self.tr(loc_key)
            tk.Label(row, text=label_text+":", font=("Segoe UI", 9, "bold"), fg=self.colors["text_dim"], bg=self.colors["bg_pane"], width=22, anchor="w").pack(side="left")
            l_val = tk.Label(row, textvariable=var, font=("Segoe UI", 9), fg=self.colors["text"], bg=self.colors["bg_pane"])
            l_val.pack(side="left")
            
            # Context menu for copying dashboard values
            m = self.create_styled_menu()
            m.add_command(label="📋 " + self.tr("copy_val"), command=lambda v=var: self.copy_string_to_clip(v.get()))
            l_val.bind("<Button-3>", lambda e, menu=m: menu.post(e.x_root, e.y_root))
            
            tk.Frame(container, bg=self.colors["bg"], height=1).pack(fill="x")

    def setup_processes(self):
        toolbar = tk.Frame(self.tab_proc, bg=self.colors["bg_pane"], padx=20, pady=15)
        toolbar.pack(fill="x")
        tk.Button(toolbar, text=self.tr("gen_tree"), command=self.load_pstree, bg=self.colors["success"], fg="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=25, pady=8, cursor="hand2").pack(side="left")
        
        tk.Label(toolbar, text="(Tip: Double-click or Right-click a process to extract it)", font=("Segoe UI", 8), fg=self.colors["text_dim"], bg=self.colors["bg_pane"]).pack(side="left", padx=20)

        self.tree_container = tk.Frame(self.tab_proc, bg=self.colors["bg_pane"], padx=20)
        self.tree_container.pack(fill="both", expand=True)
        self.proc_tree = ttk.Treeview(self.tree_container, columns=("Offset", "PID", "PPID", "Threads", "Handles"), show="tree headings")
        self.proc_tree.heading("#0", text="Process Name")
        self.proc_tree.heading("Offset", text="Offset (V)")
        self.proc_tree.heading("PID", text="PID")
        self.proc_tree.heading("PPID", text="PPID")
        self.proc_tree.heading("Threads", text="Threads")
        self.proc_tree.heading("Handles", text="Handles")
        self.proc_tree.column("#0", width=350)
        self.proc_tree.column("Offset", width=140)
        for col in ("PID", "PPID", "Threads", "Handles"): self.proc_tree.column(col, width=90, anchor="center")
        self.proc_tree.pack(fill="both", expand=True, side="left")
        
        # Threat Detection Tags
        self.proc_tree.tag_configure("suspicious", background="#ffcccc", foreground="#990000")
        self.proc_tree.tag_configure("warning", background="#ffffcc", foreground="#664d00")
        
        sb = ttk.Scrollbar(self.tree_container, orient="vertical", command=self.proc_tree.yview)
        sb.pack(fill="y", side="right")
        self.proc_tree.configure(yscrollcommand=sb.set)

        # Context Menu & Interaction
        self.proc_menu = self.create_styled_menu()
        self.proc_menu.add_command(label="📋 " + self.tr("copy_pid"), command=lambda: self.copy_to_clip(self.proc_tree, 1))
        self.proc_menu.add_command(label="📋 " + self.tr("copy_offset"), command=lambda: self.copy_to_clip(self.proc_tree, 0))
        self.proc_menu.add_command(label="🔗 " + self.tr("copy_cmdline"), command=self.get_process_cmdline)
        self.proc_menu.add_command(label="🔍 " + self.tr("view_hex"), command=lambda: self.extract_process(auto_open_hex=True))
        self.proc_menu.add_separator()
        self.proc_menu.add_command(label="📥 " + self.tr("extract_proc"), command=self.extract_process)
        self.proc_tree.bind("<Button-3>", lambda e: self.show_context_menu(e, self.proc_tree, self.proc_menu))
        self.proc_tree.bind("<Double-1>", lambda e: self.extract_process())

    def setup_envars_tab(self):
        toolbar = tk.Frame(self.tab_env, bg=self.colors["bg_pane"], padx=20, pady=15)
        toolbar.pack(fill="x")
        tk.Button(toolbar, text=self.tr("fetch_envars"), command=self.load_envars, bg=self.colors["success"], fg="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=25, pady=8, cursor="hand2").pack(side="left")
        
        tk.Label(toolbar, text=self.tr("filter_label"), font=("Segoe UI", 9), bg=self.colors["bg_pane"], fg=self.colors["text_dim"]).pack(side="left", padx=(30, 10))
        self.env_filter = tk.Entry(toolbar, font=("Segoe UI", 10), relief="flat", bg=self.colors["bg"], 
                                   highlightbackground=self.colors["border"], highlightthickness=1, width=35)
        self.env_filter.pack(side="left", ipady=5)
        self.env_filter.bind("<KeyRelease>", self.filter_envars)

        self.env_container = tk.Frame(self.tab_env, bg=self.colors["bg_pane"], padx=20)
        self.env_container.pack(fill="both", expand=True)
        self.env_tree = ttk.Treeview(self.env_container, columns=("PID", "Process", "Offset", "Variable", "Value"), show="headings")
        self.env_tree.heading("PID", text="PID", anchor="w")
        self.env_tree.heading("Process", text="Process", anchor="w")
        self.env_tree.heading("Offset", text="Offset", anchor="w")
        self.env_tree.heading("Variable", text="Variable", anchor="w")
        self.env_tree.heading("Value", text="Value", anchor="w")
        
        self.env_tree.column("PID", width=70, anchor="w")
        self.env_tree.column("Process", width=130, anchor="w")
        self.env_tree.column("Offset", width=120, anchor="w")
        self.env_tree.column("Variable", width=180, anchor="w")
        self.env_tree.column("Value", width=380, anchor="w")
        self.env_tree.pack(fill="both", expand=True, side="left")
        
        sb = ttk.Scrollbar(self.env_container, orient="vertical", command=self.env_tree.yview)
        sb.pack(fill="y", side="right")
        self.env_tree.configure(yscrollcommand=sb.set)
        
        self.all_envars = []

    def load_envars(self):
        if not self.detected_profile: return
        self.progress.start(); self.env_tree.delete(*self.env_tree.get_children())
        self.run_vol(["envars"], self.handle_envars)

    def handle_envars(self, out, err):
        self.progress.stop()
        self.all_envars = []
        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            if not line or "Pid" in line and "Variable" in line: continue
            parts = line.split(None, 4)
            if len(parts) >= 5 and parts[0].isdigit():
                self.all_envars.append((parts[0], parts[1], parts[2], parts[3], parts[4]))
            elif len(parts) == 4 and parts[0].isdigit():
                # Case where Value is empty
                self.all_envars.append((parts[0], parts[1], parts[2], parts[3], ""))
        
        self.refresh_env_view(self.all_envars)
        self.update_status(f"Loaded {len(self.all_envars)} environment variables.")
        if self.ai_enabled:
            self.ask_ai("Analyze these environment variables for suspicious entries:", out)

    def refresh_env_view(self, data):
        self.env_tree.delete(*self.env_tree.get_children())
        for item in data[:2000]: # Performance cap
            self.env_tree.insert("", "end", values=item)

    def filter_envars(self, event):
        query = self.env_filter.get().lower()
        filtered = [item for item in self.all_envars if any(query in str(x).lower() for x in item)]
        self.refresh_env_view(filtered)


    def setup_files_tab(self):
        toolbar = tk.Frame(self.tab_files, bg=self.colors["bg_pane"], padx=20, pady=15)
        toolbar.pack(fill="x")
        tk.Button(toolbar, text=self.tr("scan_files"), command=self.load_files, bg=self.colors["success"], fg="white", relief="flat", font=("Segoe UI", 9, "bold"), padx=25, pady=8).pack(side="left")
        tk.Label(toolbar, text="(Tip: Double-click or Right-click a file to extract it)", font=("Segoe UI", 8), fg=self.colors["text_dim"], bg=self.colors["bg_pane"]).pack(side="left", padx=20)
        
        self.file_container = tk.Frame(self.tab_files, bg=self.colors["bg_pane"], padx=20)
        self.file_container.pack(fill="both", expand=True)
        self.file_tree = ttk.Treeview(self.file_container, columns=("Offset", "Ptr", "Hnd", "Access"), show="tree headings")
        self.file_tree.heading("#0", text="File Path")
        self.file_tree.heading("Offset", text="Offset (P)")
        self.file_tree.heading("Ptr", text="#Ptr")
        self.file_tree.heading("Hnd", text="#Hnd")
        self.file_tree.heading("Access", text="Access")
        self.file_tree.column("#0", width=500)
        self.file_tree.column("Offset", width=140)
        for col in ("Ptr", "Hnd", "Access"): self.file_tree.column(col, width=80, anchor="center")
        self.file_tree.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(self.file_container, orient="vertical", command=self.file_tree.yview)
        sb.pack(fill="y", side="right")
        self.file_tree.configure(yscrollcommand=sb.set)

        # Context Menu & Interaction for Files
        self.file_menu = self.create_styled_menu()
        self.file_menu.add_command(label="📋 Copy Path", command=lambda: self.copy_to_clip(self.file_tree, -1))
        self.file_menu.add_separator()
        self.file_menu.add_command(label="📥 Extract File (dumpfiles)", command=self.extract_file)
        self.file_tree.bind("<Button-3>", lambda e: self.show_context_menu(e, self.file_tree, self.file_menu))
        self.file_tree.bind("<Double-1>", lambda e: self.extract_file())

    def show_context_menu(self, event, tree, menu):
        item = tree.identify_row(event.y)
        if item:
            tree.selection_set(item)
            menu.post(event.x_root, event.y_root)

    def setup_security(self):
        container = tk.Frame(self.tab_sec, bg=self.colors["bg_pane"], padx=25, pady=25)
        container.pack(fill="both", expand=True)

        # Toolbar
        header_sec = tk.Frame(container, bg=self.colors["bg_pane"])
        header_sec.pack(fill="x", pady=(0,20))
        
        tk.Button(header_sec, text=self.tr("run_hashdump"), command=self.run_hashdump, 
                  bg=self.colors["accent"], fg="white", font=("Segoe UI", 9, "bold"), 
                  relief="flat", padx=20, pady=10).pack(side="left")

        # Brute-force Section
        bf_frame = tk.Frame(header_sec, bg=self.colors["bg_pane"])
        bf_frame.pack(side="right")
        
        self.wordlist_btn = tk.Button(bf_frame, text="📁 " + self.tr("select_wordlist"), command=self.select_wordlist,
                                      bg=self.colors["bg"], fg=self.colors["text"], font=("Segoe UI", 9),
                                      relief="flat", padx=15, pady=10)
        self.wordlist_btn.pack(side="left", padx=5)
        
        self.crack_btn = tk.Button(bf_frame, text="🔥 " + self.tr("crack_btn"), command=self.run_bruteforce,
                                   bg=self.colors["danger"], fg="white", font=("Segoe UI", 9, "bold"),
                                   relief="flat", padx=20, pady=10, state="disabled")
        self.crack_btn.current_bg = self.colors["danger"]
        self.crack_btn.pack(side="left", padx=5)
        
        self.stop_btn = tk.Button(bf_frame, text="🛑 " + self.tr("stop_btn"), command=self.stop_bruteforce,
                                 bg=self.colors["border"], fg="white", font=("Segoe UI", 9, "bold"),
                                 relief="flat", padx=20, pady=10, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        # Progress Info
        self.crack_progress = tk.Label(container, text="", font=("Segoe UI", 9, "italic"),
                                      bg=self.colors["bg_pane"], fg=self.colors["accent"])
        self.crack_progress.pack(pady=(0, 10))

        # Hash Table (Treeview)
        self.hash_container = tk.Frame(container, bg=self.colors["bg_pane"])
        self.hash_container.pack(fill="both", expand=True)
        
        cols = ("User", "RID", "LM", "NTLM", "Password")
        self.hash_tree = ttk.Treeview(self.hash_container, columns=cols, show="headings", selectmode="extended")
        
        self.hash_tree.heading("User", text=self.tr("col_user"), anchor="w")
        self.hash_tree.heading("RID", text=self.tr("col_rid"), anchor="center")
        self.hash_tree.heading("LM", text=self.tr("col_lm"), anchor="w")
        self.hash_tree.heading("NTLM", text=self.tr("col_ntlm"), anchor="w")
        self.hash_tree.heading("Password", text=self.tr("col_pass"), anchor="w")
        
        self.hash_tree.column("User", width=150, anchor="w")
        self.hash_tree.column("RID", width=80, anchor="center")
        self.hash_tree.column("LM", width=250, anchor="w")
        self.hash_tree.column("NTLM", width=250, anchor="w")
        self.hash_tree.column("Password", width=200, anchor="w")
        
        self.hash_tree.pack(fill="both", expand=True, side="left")
        
        sb = ttk.Scrollbar(self.hash_container, orient="vertical", command=self.hash_tree.yview)
        sb.pack(fill="y", side="right")
        self.hash_tree.configure(yscrollcommand=sb.set)

        # Context Menu for Hashes
        self.hash_menu = self.create_styled_menu()
        self.hash_menu.add_command(label="👤 " + self.tr("copy_user"), command=lambda: self.copy_to_clip(self.hash_tree, 0))
        self.hash_menu.add_command(label="🔑 " + self.tr("copy_lm"), command=lambda: self.copy_to_clip(self.hash_tree, 2))
        self.hash_menu.add_command(label="🔑 " + self.tr("copy_ntlm"), command=lambda: self.copy_to_clip(self.hash_tree, 3))
        self.hash_menu.add_command(label="🔓 " + self.tr("copy_pass"), command=lambda: self.copy_to_clip(self.hash_tree, 4))
        self.hash_menu.add_separator()
        self.hash_menu.add_command(label="📋 " + self.tr("copy_row"), command=lambda: self.copy_row(self.hash_tree))
        self.hash_tree.bind("<Button-3>", lambda e: self.show_context_menu(e, self.hash_tree, self.hash_menu))

    # --- Logic ---

    def update_status(self, text): self.status_bar.config(text=f" {text}")

    def run_vol(self, args, callback):
        if not self.current_dump: return
        cmd = [self.vol_path, "-f", self.current_dump] + args
        if self.detected_profile and "--profile" not in args: cmd.insert(4, "--profile=" + self.detected_profile)
        
        def _exec():
            try:
                self.root.after(0, self.task_started, args[0])
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace')
                out, err = process.communicate()
                
                final_out = out if out is not None else ""
                final_err = err if err is not None else ""
                
                self.root.after(0, lambda: self.task_finished(args[0], final_out, final_err, callback))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda: messagebox.showerror("Error", err_msg))
                self.root.after(0, self.decrement_task)
        threading.Thread(target=_exec).start()

    def task_started(self, cmd_name):
        self.active_tasks += 1
        self.progress.start()
        self.task_label.config(text=f"{self.active_tasks} ACTIVE")
        self.update_status(f"Running {cmd_name}...")

    def task_finished(self, cmd_name, out, err, callback):
        self.decrement_task()
        # Count lines/items for a quick summary
        item_count = len(out.splitlines()) if out else 0
        summary = f"✔ {cmd_name} finished ({item_count} lines)" if item_count > 0 else f"✔ {cmd_name} finished."
        if err.strip(): summary += " [!] See Console"
        self.update_status(summary)
        callback(out, err)

    def decrement_task(self):
        self.active_tasks -= 1
        if self.active_tasks <= 0:
            self.active_tasks = 0
            self.progress.stop()
            self.task_label.config(text="")
        else:
            self.task_label.config(text=f"{self.active_tasks} ACTIVE")

    def load_dump(self):
        file_path = filedialog.askopenfilename(filetypes=[(self.tr("app_title"), "*.dmp *.raw *.img"), ("All", "*.*")])
        if file_path:
            self.current_dump = file_path
            self.file_status.config(text=os.path.basename(file_path))
            self.meta_vars["dump_loc"].set(file_path)
            
            # Reset UI trees for a fresh load
            for tree in [self.proc_tree, self.file_tree, self.env_tree, self.hash_tree]:
                tree.delete(*tree.get_children())
            
            self.progress.start()
            self.run_vol(["imageinfo"], self.handle_imageinfo)

    def handle_imageinfo(self, out, err):
        self.progress.stop()
        
        # Reset meta vars to Analyzing status to avoid false info display
        self.meta_vars["computer_name"].set("⌛ Analyzing...")
        self.meta_vars["primary_user"].set("⌛ Analyzing...")
        
        # Suggested Profiles
        match_prof = re.search(r"Suggested Profile\(s\) : (.*)", out)
        if match_prof:
            profile = match_prof.group(1).split(",")[0].strip()
            self.detected_profile = profile
            self.meta_vars["vol_profile"].set(profile)
            if "x64" in out or "x64" in profile: self.meta_vars["sys_arch"].set("x64 (64-bit)")
            elif "x86" in out or "x86" in profile: self.meta_vars["sys_arch"].set("x86 (32-bit)")
        
        # Additional Metadata
        m_time = re.search(r"Image date and time : (.*)", out)
        if m_time: self.meta_vars["sys_time"].set(m_time.group(1).strip())
        
        m_cpus = re.search(r"Number of CPUs : (.*)", out)
        if m_cpus: self.meta_vars["num_cpus"].set(m_cpus.group(1).strip())
        
        m_kdbg = re.search(r"KDBG : (.*)", out)
        if m_kdbg: self.meta_vars["kdbg_addr"].set(m_kdbg.group(1).strip())

        m_sp = re.search(r"Service Pack \(NT\) : (.*)", out)
        if m_sp: self.meta_vars["service_pack"].set(m_sp.group(1).strip())

        if self.detected_profile:
            self.progress.start()
            self.run_vol(["hivelist"], self.handle_hivelist)

    def handle_hivelist(self, out, err):
        # Reset hives
        self.hives = {}
        lines = out.splitlines()
        for line in lines:
            line_u = line.upper()
            # Find the offset (first hex number)
            offset_match = re.search(r"(0x[0-9a-fA-F]+)", line)
            if not offset_match: continue
            offset = offset_match.group(1)

            # More liberal search for SYSTEM and SAM hives
            if "SYSTEM" in line_u and ("CONFIG" in line_u or "ROOT" in line_u or "REGISTRY" in line_u):
                self.hives['SYSTEM'] = offset
            if "SAM" in line_u and ("CONFIG" in line_u or "ROOT" in line_u or "REGISTRY" in line_u):
                self.hives['SAM'] = offset
        
        # Metadata Discovery Batch
        self.metadata_probes_pending = 0
        self.metadata_candidates = {"pc": Counter(), "user": Counter()}

        def _probe_metadata(args, cb):
            self.metadata_probes_pending += 1
            self.run_vol(args, lambda o, e: [cb(o, e), self._decrement_metadata_probe()])

        # Priority 1: Computer Name from SYSTEM hive
        if 'SYSTEM' in self.hives:
            _probe_metadata(["printkey", "-o", self.hives['SYSTEM'], "-K", r"ControlSet001\Control\ComputerName\ComputerName"], self.handle_compname)
            _probe_metadata(["printkey", "-o", self.hives['SYSTEM'], "-K", r"ControlSet001\Control\ComputerName\ActiveComputerName"], self.handle_compname)
            _probe_metadata(["printkey", "-o", self.hives['SYSTEM'], "-K", r"ControlSet002\Control\ComputerName\ComputerName"], self.handle_compname)
        
        # Priority 2: User list from SAM/SYSTEM (populate Security tab automatically)
        if 'SYSTEM' in self.hives and 'SAM' in self.hives:
            _probe_metadata(["hashdump", "-y", self.hives['SYSTEM'], "-s", self.hives['SAM']], self.handle_hash_ui)
        
        # Priority 3 (Authoritative): Envars search
        _probe_metadata(["envars"], lambda o, e: [self.handle_envars_fallback(o, e), self.handle_envars(o, e)])

    def _decrement_metadata_probe(self):
        self.metadata_probes_pending -= 1
        if self.metadata_probes_pending <= 0:
            self.commit_metadata_to_ui()

    def commit_metadata_to_ui(self):
        if self.metadata_candidates["pc"]:
            winner = self.metadata_candidates["pc"].most_common(1)[0][0]
            self.meta_vars["computer_name"].set(winner)
        else:
            self.meta_vars["computer_name"].set("Not found")

        if self.metadata_candidates["user"]:
            winner = self.metadata_candidates["user"].most_common(1)[0][0]
            self.meta_vars["primary_user"].set(winner)
        else:
            self.meta_vars["primary_user"].set("Not found")
        
        self.update_status(f"Discovery complete: {self.meta_vars['computer_name'].get()} / {self.meta_vars['primary_user'].get()}")

    def handle_envars_fallback(self, out, err):
        # Extract metadata using frequency analysis (most common value wins)
        for line in out.splitlines():
            line = line.strip()
            if not line or "Pid" in line and "Variable" in line: continue
            
            # Match data lines: PID then Process then Variable then Value
            parts = line.split(None, 3) 
            
            if len(parts) >= 4 and parts[0].isdigit():
                var_name = parts[2].upper().strip()
                val = parts[3].strip()
                
                # Filter out obvious headers or junk
                junk_vals = ["value", "stable", "volatile", "(v)", "(s)", "minint", "-v"]
                if not val or any(j in val.lower() for j in junk_vals) or len(val) < 2:
                    continue

                if var_name == "COMPUTERNAME":
                    self.metadata_candidates["pc"][val] += 5 # High weight for envars
                
                if var_name == "USERNAME":
                    # Filter system accounts
                    system_accs = ["system", "local service", "network service", "anonymous logon"]
                    if val.lower() not in system_accs:
                        self.metadata_candidates["user"][val] += 5
        
        # Global regex search for COMPUTERNAME
        regex_matches = re.findall(r"COMPUTERNAME\s+([A-Z0-9\-]{3,15})", out, re.IGNORECASE)
        for m in regex_matches: self.metadata_candidates["pc"][m] += 5
        
        self.update_status(f"Metadata detected: {self.meta_vars['computer_name'].get()} / {self.meta_vars['primary_user'].get()}")
        if self.ai_enabled:
            self.ask_ai("Analyze these environment variables for suspicious entries (persistence, unusual paths, proxy settings):", out)

    def handle_hash_silent(self, out, err):
        # Parse hashdump: User:RID:LM:NTLM:::
        for line in out.splitlines():
            if ":" in line:
                parts = line.split(":")
                if len(parts) > 0:
                    username = parts[0].strip()
                    if username:
                        # Give hashdump strong weight for username
                        system_accounts = ["administrator", "guest", "defaultaccount", "wdagutilityaccount", "krbtgt"]
                        if username.lower() not in system_accounts:
                            self.metadata_candidates["user"][username] += 10
                        else:
                            self.metadata_candidates["user"][username] += 1

    def handle_compname(self, out, err):
        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Stricter: only match if line contains 'Value', 'ComputerName' or similar to avoid false positives
            if not re.search(r"ComputerName|Value|Active", line, re.I): continue

            # Common patterns in printkey (S) string or (U) unicode
            match = re.search(r":\s+\([SU]\)\s+([^\r\n]+)", line)
            
            if match:
                val = match.group(1).strip().strip('"')
                val = re.split(r"\s+[\[=]", val)[0].strip()
                
                # Filter out hive names and common placeholders
                if val and len(val) > 1 and val.lower() not in ["computername", "system", "sam", "registry", "controlset001"]:
                    self.metadata_candidates["pc"][val] += 1
        
        self.update_status(f"CompName detection: {self.meta_vars['computer_name'].get()}")

    # --- Processes ---
    def load_pstree(self):
        if not self.detected_profile: return
        self.progress.start(); self.proc_tree.delete(*self.proc_tree.get_children())
        self.run_vol(["pstree"], self.handle_pstree)

    def handle_pstree(self, out, err):
        self.progress.stop()
        lines = out.splitlines(); start = 0
        for i, l in enumerate(lines):
            if "Name" in l and "PID" in l: start = i + 2; break
        stack = {0: ""}; all_nodes = []
        for line in lines[start:]:
            if not line.strip(): continue
            match = re.match(r"([\.\s]*)(?:(0x[0-9a-fA-F]+):)?(.*?)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", line)
            if match:
                dots, offset, name, pid, ppid, threads, handles = match.groups()
                depth = dots.count("."); offset = offset or "N/A"
                icon = "⚙ " if "svchost" in name.lower() else "💻 " if "explorer" in name.lower() else "🛡 " if "lsass" in name.lower() or "services" in name.lower() else "   "
                parent = stack.get(depth - 1, "") if depth > 0 else ""
                node = self.proc_tree.insert(parent, "end", text=f"{icon}{name.strip()}", values=(offset, pid, ppid, threads, handles))
                stack[depth] = node; all_nodes.append(node)
        for node in all_nodes: self.proc_tree.item(node, open=True)
        self.update_status("Processes Loaded")
        if self.ai_enabled:
            threat_prompt = (
                "ACT AS A FORENSIC ANALYST. Review the process tree for POTENTIAL threats.\n"
                "BE PROACTIVE: Flag any relationship that looks unusual, even if you are not certain it is malicious.\n\n"
                "AUTOMATIC SUSPICION (Always Flag):\n"
                "- Any Productivity app (Office, LibreOffice, PDF Reader) launching a shell (powershell, cmd, wscript, cscript).\n"
                "- Any Browser launching a shell or system utility (net.exe, ipconfig, etc.).\n"
                "- System processes (lsass, services, taskhost) with non-system children.\n\n"
                "EXCLUSIONS (NEVER FLAG):\n"
                "- services.exe -> svchost.exe (This is standard behavior).\n"
                "- explorer.exe -> legitimate user apps (Chrome, Outlook, etc.).\n"
                "- Any svchost.exe process unless it is misspelled or in a completely wrong tree (e.g. launched by a browser).\n\n"
                "ID RULES:\n"
                "- Flag the PARENT process as the primary suspect.\n"
                "- You can provide the DECIMAL PID (e.g. 1234) OR the memory offset.\n"
                "- CRITICAL: Every memory offset MUST start with '0x' (e.g. 0x8a123...). Never omit the '0x'.\n\n"
                "CRITICAL: If you find suspicious PIDs, you MUST include: [FLAG_PIDS: ID1, ID2]"
            )
            self.ask_ai(threat_prompt, out)

    def extract_process(self, auto_open_hex=False):
        sel = self.proc_tree.selection()
        if not sel: return messagebox.showwarning("Selection", "Select a process.")
        
        item_data = self.proc_tree.item(sel[0])
        offset = item_data['values'][0]
        pid = item_data['values'][1]
        name = item_data['text'].strip()

        if offset == "N/A" or not offset:
            return messagebox.showerror("Extraction Error", f"Process '{name}' (PID {pid}) does not have a valid memory offset and cannot be extracted.")

        path = os.path.join(os.getcwd(), "extracted", "processes")
        if not os.path.exists(path): os.makedirs(path)
        
        self.update_status(f"Attempting to extract PID {pid}...")
        
        def _on_done(out, err):
            if "OK:" in out or "Written to" in out or "Saved" in out:
                self.update_status(f"Process {pid} dumped to {path}")
                if auto_open_hex:
                    # Find the dumped file (usually named executable.PID.exe or similar)
                    files = [f for f in os.listdir(path) if f".{pid}." in f or f"pid.{pid}" in f.lower()]
                    if files:
                        target = os.path.join(path, files[0])
                        self.root.after(0, lambda: HexViewer(self.root, target, self.colors))
                    else:
                        messagebox.showinfo("Extraction Done", f"Process dumped to {path}")
                else:
                    messagebox.showinfo("Extraction Success", f"Process {pid} dumped to {path}")
            else:
                error_msg = err if err.strip() else out
                messagebox.showerror("Extraction Failed", f"Could not extract process.\n\nReason:\n{error_msg[:200]}")

        self.run_vol(["procdump", "-p", str(pid), "--dump-dir", path], _on_done)

    def get_process_cmdline(self):
        sel = self.proc_tree.selection()
        if not sel: return
        pid = self.proc_tree.item(sel[0])['values'][1]
        self.update_status(f"Fetching command line for PID {pid}...")
        self.run_vol(["cmdline", "-p", str(pid)], self.handle_cmdline_result)

    def handle_cmdline_result(self, out, err):
        # cmdline output: "Process.exe pid: 123 \n Command line : C:\Path\Args"
        match = re.search(r"Command line\s*:\s*(.*)", out, re.IGNORECASE)
        if match:
            cmdline = match.group(1).strip().strip('"')
            self.copy_string_to_clip(cmdline)
            self.update_status(f"Command line copied: {cmdline[:40]}...")
        else:
            self.update_status("Could not retrieve command line.")


    # --- NEW: Files Logic ---
    def load_files(self):
        if not self.detected_profile: return
        self.progress.start(); self.file_tree.delete(*self.file_tree.get_children())
        self.run_vol(["filescan"], self.handle_filescan)

    def handle_filescan(self, out, err):
        self.progress.stop()
        lines = out.splitlines(); start = 0
        for i, l in enumerate(lines):
            if "Offset" in l and "Name" in l: start = i + 2; break
        for line in lines[start:]:
            if not line.strip(): continue
            parts = line.split(None, 4)
            if len(parts) >= 5:
                offset, ptr, hnd, access, name = parts
                self.file_tree.insert("", "end", text=name, values=(offset, ptr, hnd, access))
        self.update_status("Files Loaded")
        if self.ai_enabled:
            self.ask_ai("Analyze this filescan output for suspicious filenames, locations (e.g., Temp, AppData), or extensions (e.g., .double.exe, script files in sys32):", out)

    def handle_envars_tab(self, out, err):
        self.progress.stop()
        lines = out.splitlines()
        for line in lines:
            line = line.strip()
            if not line or "Pid" in line and "Variable" in line: continue
            parts = line.split(None, 3)
            if len(parts) >= 4 and parts[0].isdigit():
                pid, proc, var, val = parts
                self.env_tree.insert("", "end", values=(pid, proc, var, val))
        self.update_status("Environment Variables Loaded")
        if self.ai_enabled:
            self.ask_ai("Analyze these environment variables for suspicious entries (persistence, unusual paths, proxy settings):", out)

    def extract_file(self):
        sel = self.file_tree.selection()
        if not sel: return messagebox.showwarning("Selection", "Select a file.")
        
        item_data = self.file_tree.item(sel[0])
        offset = item_data['values'][0]
        name = item_data['text'].strip()

        if offset == "N/A" or not offset:
            return messagebox.showerror("Extraction Error", "This file object does not have a valid offset and cannot be extracted.")

        path = os.path.join(os.getcwd(), "extracted", "files")
        if not os.path.exists(path): os.makedirs(path)
        
        self.update_status(f"Extracting file at {offset}...")
        self.last_extract_target = name
        self.run_vol(["dumpfiles", "-Q", offset, "--dump-dir", path], self.handle_extract_file)

    def handle_extract_file(self, out, err):
        # Volatility 2 dumpfiles success usually lists DataSectionObject, etc.
        if "DataSectionObject" in out or "ImageSectionObject" in out or "SharedCacheMap" in out:
            dump_dir = os.path.join(os.getcwd(), "extracted", "files")
            original_name = os.path.basename(self.last_extract_target) if hasattr(self, "last_extract_target") else "unknown"
            
            # Find the file created by Volatility (it contains the offset in its name)
            renamed = False
            for f in os.listdir(dump_dir):
                if ".dat" in f or ".vac" in f or ".img" in f:
                    # Generic Volatility name: file.None.0xOFFSET.img
                    try:
                        old_path = os.path.join(dump_dir, f)
                        new_path = os.path.join(dump_dir, original_name)
                        
                        # Avoid overwriting or clean naming
                        if not os.path.exists(new_path):
                            os.rename(old_path, new_path)
                            renamed = True
                    except: pass
            
            msg = f"File successfully dumped to extracted/files/"
            if renamed: msg += f"\nRenamed to: {original_name}"
            messagebox.showinfo("Extraction Success", msg)
        else:
            error_msg = err if err.strip() else out
            if not error_msg.strip(): error_msg = "Possible paging issue or invalid offset."
            messagebox.showerror("Extraction Failed", f"Could not extract file at this offset.\n\nReason:\n{error_msg[:200]}")

    # --- Security ---
    def run_hashdump(self, retry=True):
        self.hash_tree.delete(*self.hash_tree.get_children())
        if 'SYSTEM' not in self.hives or 'SAM' not in self.hives:
            if retry:
                self.update_status("Scanning memory for registry hives...")
                self.run_vol(["hivelist"], lambda o, e: [self.handle_hivelist(o,e), self.run_hashdump(retry=False)])
            else:
                self.sec_output.insert(tk.END, "[!] Error: Hives missing (SAM or SYSTEM).\n")
                self.sec_output.insert(tk.END, "[Tip] Try loading the dump again or verify the Volatility profile.\n")
                messagebox.showwarning("Security", "SAM/SYSTEM hives missing. Cannot perform hashdump.")
        else:
            self.update_status("Cracking hashes...")
            self.run_vol(["hashdump", "-y", self.hives['SYSTEM'], "-s", self.hives['SAM']], self.handle_hash_ui)

    def handle_hash_ui(self, out, err):
        if not out.strip() and err.strip():
            messagebox.showerror("Security", f"Errors during hashdump:\n{err}")
        
        # Parse hashes for cracking
        self.hashes_found = []
        for line in out.splitlines():
            if ":" in line:
                parts = line.split(":")
                if len(parts) >= 4:
                    user = parts[0]
                    rid = parts[1]
                    lm = parts[2]
                    ntlm = parts[3]
                    self.hash_tree.insert("", "end", values=(user, rid, lm, ntlm, ""))
                    self.hashes_found.append((user, ntlm))
        
        if self.hashes_found:
            self.crack_btn.config(state="normal")
            self.update_status(f"Found {len(self.hashes_found)} hashes. Select users to crack.")
            
        self.handle_hash_silent(out, err)

    def select_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Wordlist", "*.txt"), ("All", "*.*")])
        if path:
            self.wordlist_path = path
            self.wordlist_btn.config(text="✔ " + os.path.basename(path)[:15], bg=self.colors["success"], fg="white")

    def run_bruteforce(self):
        if not self.wordlist_path:
            return messagebox.showwarning("Brute-force", self.tr("select_wordlist"))
        
        selection = self.hash_tree.selection()
        if not selection:
            return messagebox.showwarning("Brute-force", "Please select one or more rows in the hash table to crack.")

        targets = []
        for item in selection:
            vals = self.hash_tree.item(item)['values']
            if not vals[4]: # Only target uncracked ones
                targets.append({"id": item, "user": vals[0], "hash": vals[3]})
                self.hash_tree.set(item, "Password", self.tr("cracking_row_status"))

        if not targets: return

        def _crack_thread():
            self.stop_cracking.clear()
            # Set button to 'inactive' look (light red)
            self.root.after(0, lambda: self.crack_btn.config(state="disabled", bg="#ff9999"))
            self.root.after(0, lambda: self.stop_btn.config(state="normal", bg=self.colors["danger"]))
            
            total_words = 0
            try:
                with open(self.wordlist_path, "rb") as f:
                    for _ in f: total_words += 1
            except: total_words = 1
            
            cracked_count = 0
            tested_count = 0
            
            try:
                with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if self.stop_cracking.is_set(): break
                        candidate = line.strip()
                        if not candidate: continue
                        
                        h = ntlm_hash(candidate)
                        tested_count += 1
                        
                        # Compare against selected targets
                        for t in targets[:]: # Use copy to allow removal
                            if h.lower() == t["hash"].lower():
                                cracked_count += 1
                                self.root.after(0, lambda i=t["id"], p=candidate: self.hash_tree.set(i, "Password", p))
                                targets.remove(t) # Stop searching for this one!

                        if not targets: break # All targets found!
                        
                        if tested_count % 500 == 0:
                            perc = int((tested_count / total_words) * 100)
                            prog_text = self.tr("crack_progress").format(perc, tested_count, total_words)
                            self.root.after(0, lambda t=prog_text: self.crack_progress.config(text=t))

            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Cracking Error", str(e)))

            # Reset status for remaining uncracked targets if stopped/finished
            for t in targets:
                self.root.after(0, lambda i=t["id"]: self.hash_tree.set(i, "Password", ""))

            self.root.after(0, lambda: self.update_status(f"Cracking complete. {cracked_count} passwords found."))
            self.root.after(0, lambda: self.crack_btn.config(state="normal", bg=self.colors["danger"]))
            self.root.after(0, lambda: self.stop_btn.config(state="disabled", bg=self.colors["border"]))
            self.root.after(0, lambda: self.crack_progress.config(text=""))
            
            if cracked_count > 0 and self.ai_enabled:
                self.ask_ai("Analyze these cracked passwords for patterns (e.g., complexity, reused words, forensic links):", 
                            f"Passwords found: {cracked_count}")

        threading.Thread(target=_crack_thread, daemon=True).start()

    def stop_bruteforce(self):
        self.stop_cracking.set()
        self.update_status("Stopping brute-force...")

    def copy_to_clip(self, tree, col_idx):
        sel = tree.selection()
        if not sel: return
        val = tree.item(sel[0])['values'][col_idx] if col_idx != -1 else tree.item(sel[0])['text']
        self.copy_string_to_clip(val)

    def copy_string_to_clip(self, val):
        self.root.clipboard_clear()
        self.root.clipboard_append(str(val))
        self.update_status(f"Copied: {str(val)[:30]}...")

    def copy_row(self, tree):
        sel = tree.selection()
        if not sel: return
        vals = tree.item(sel[0])['values']
        self.copy_string_to_clip("\t".join(map(str, vals)))

    def create_styled_menu(self):
        """Creates a professional dark-themed context menu."""
        menu = tk.Menu(self.root, tearoff=0, 
                       bg=self.colors["bg_pane"], 
                       fg=self.colors["text"],
                       activebackground=self.colors["accent"],
                       activeforeground="white",
                       font=("Segoe UI", 9),
                       relief="flat",
                       borderwidth=1)
        return menu

    # --- AI Assistant (Panel Version) ---
    def setup_ai_panel(self):
        # Clear panel if re-setup
        for widget in self.ai_panel.winfo_children(): widget.destroy()
        
        toolbar = tk.Frame(self.ai_panel, bg=self.colors["header"], padx=20, pady=15)
        toolbar.pack(fill="x")
        
        tk.Label(toolbar, text="🤖 " + self.tr("tab_ai").strip(), font=("Segoe UI", 11, "bold"), 
                 bg=self.colors["header"], fg="white").pack(side="left")
        
        self.ai_status_label = tk.Label(toolbar, text=self.tr("ai_ready"), font=("Segoe UI", 8),
                                        bg=self.colors["header"], fg=self.colors["border"])
        self.ai_status_label.pack(side="right")
        
        container = tk.Frame(self.ai_panel, bg=self.colors["bg_pane"], padx=10, pady=10)
        container.pack(fill="both", expand=True)
        
        self.ai_output = tk.Text(container, bg=self.colors["console_bg"], fg=self.colors["console_fg"],
                                 font=("Consolas", 10), relief="flat", padx=15, pady=15, wrap="word")
        self.ai_output.pack(side="left", fill="both", expand=True)
        
        sb = tk.Scrollbar(container, command=self.ai_output.yview)
        sb.pack(side="right", fill="y")
        self.ai_output.config(yscrollcommand=sb.set)
        
        self.ai_output.insert(tk.END, ">>> OSINT & Memory Analysis AI Assistant Ready.\n")
        self.ai_output.insert(tk.END, ">>> Instructions: Load data to trigger analysis.\n\n")
        self.ai_output.config(state="disabled")

    def toggle_ai_panel(self):
        if self.ai_visible:
            self.ai_panel.pack_forget()
            self.ai_visible = False
        else:
            self.ai_panel.pack(side="right", fill="y", padx=(10, 0))
            self.ai_visible = True

    def flag_suspicious_processes(self, pids):
        # Clear previous flags
        for item in self.proc_tree.get_children():
            self._clear_tags_recursive(item)
            
        match_count = 0
        for pid in pids:
            target = str(pid).strip()
            for item in self.proc_tree.get_children(): # Start from root level
                if self._flag_recursive(item, target):
                    match_count += 1
        
        if match_count > 0:
            self.update_status(f"⚠ {match_count} suspicious processes flagged in the tree!")
        else:
            self.update_status("AI suggested PIDs, but they were not found in the current tree.")

    def _clear_tags_recursive(self, item):
        self.proc_tree.item(item, tags=())
        # Restore name (remove icons)
        curr_text = self.proc_tree.item(item, 'text')
        for icon in ["⚠️ ", "🔗 "]:
            if icon in curr_text:
                curr_text = curr_text.replace(icon, "")
        self.proc_tree.item(item, text=curr_text)
            
        for child in self.proc_tree.get_children(item):
            self._clear_tags_recursive(child)

    def _flag_descendants_warning(self, item):
        for child in self.proc_tree.get_children(item):
            self.proc_tree.item(child, tags=("warning",))
            # Add subtle link icon
            curr_text = self.proc_tree.item(child, 'text')
            if "🔗 " not in curr_text and "⚠️ " not in curr_text:
                self.proc_tree.item(child, text="🔗 " + curr_text)
            self._flag_descendants_warning(child)

    def _flag_recursive(self, item, target_pid):
        vals = self.proc_tree.item(item, 'values')
        if not vals or len(vals) < 2: return False
        
        # Get PID and strip any non-digit chars just in case
        item_pid = str(vals[1]).strip()
        
        if item_pid == target_pid:
            self.proc_tree.item(item, tags=("suspicious",))
            # Add emoji
            curr_text = self.proc_tree.item(item, 'text')
            if "⚠️ " not in curr_text:
                self.proc_tree.item(item, text="⚠️ " + curr_text)
            
            # Flag all children as warnings
            self._flag_descendants_warning(item)
            
            # Ensure parent is open
            parent = self.proc_tree.parent(item)
            while parent:
                self.proc_tree.item(parent, open=True)
                parent = self.proc_tree.parent(parent)
            return True
            
        for child in self.proc_tree.get_children(item):
            if self._flag_recursive(child, target_pid):
                return True
        return False

    def ask_ai(self, prompt, context_data):
        if not self.ai_enabled: return
        
        # Multilingual Support
        lang = self.lang_var.get()
        lang_instruction = "IMPORTANT: Respond in FRENCH." if lang == "fr" else "IMPORTANT: Respond in ENGLISH."
        
        def _ai_thread():
            self.root.after(0, lambda: self.ai_status_label.config(text=self.tr("ai_analyzing"), fg=self.colors["accent"]))
            
            full_prompt = f"{lang_instruction}\n\n{prompt}\n\nPlease analyze the following data for suspicious activity or forensic artifacts:\n\nDATA TO ANALYZE:\n{context_data[:5000]}"
            
            try:
                payload = {
                    "model": self.ai_model,
                    "prompt": full_prompt,
                    "stream": False
                }
                response = requests.post(self.ai_url, json=payload, timeout=self.ai_timeout)
                if response.status_code == 200:
                    result = response.json().get("response", "No response from AI.")
                    self.root.after(0, lambda: self.update_ai_ui(result))
                else:
                    self.root.after(0, lambda: self.update_ai_ui(f"Error: {response.status_code} - {response.text}"))
            except requests.exceptions.Timeout:
                self.root.after(0, lambda: self.update_ai_ui(self.tr("ai_timeout_err")))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda: self.update_ai_ui(f"Error: {err_msg}"))
            
            self.root.after(0, lambda: self.ai_status_label.config(text=self.tr("ai_ready"), fg=self.colors["border"]))

        threading.Thread(target=_ai_thread, daemon=True).start()

    def update_ai_ui(self, text):
        # Auto-show panel if hidden when data arrives
        if not self.ai_visible:
            self.toggle_ai_panel()
            
        self.ai_output.config(state="normal")
        self.ai_output.insert(tk.END, f"\n--- AI ANALYSIS [{self.ai_model}] ---\n{text}\n\n")
        self.ai_output.see(tk.END)
        self.ai_output.config(state="disabled")
        self.update_status("AI Analysis Complete.")
        
        # Parse for Flagged PIDs (extra robust for spaces, multiple blocks, and hex)
        flag_iter = re.finditer(r"FLAG\\?_PIDS?\s*:\s*([0-9a-fx\s,]+)", text, re.IGNORECASE)
        found_identifiers = []
        
        for match in flag_iter:
            # Extract numbers, hex with 0x, or pure hex strings (a-f, 8+ chars)
            ids_in_block = re.findall(r"0x[0-9a-fA-F]+|[0-9a-fA-F]{7,16}|\b\d+\b", match.group(1))
            found_identifiers.extend(ids_in_block)

        if found_identifiers:
            pids = []
            for identifier in found_identifiers:
                identifier = identifier.lower().strip()
                # Heuristic: If it has 0x, or letters a-f, or is very long (offsets are typically long)
                is_likely_offset = "0x" in identifier or any(c in "abcdef" for c in identifier) or len(identifier) > 6
                
                if is_likely_offset:
                    # Clean up for the flagger (ensure 0x prefix)
                    full_id = identifier if identifier.startswith("0x") else "0x" + identifier
                    self.flag_by_offset_or_pid(full_id)
                else:
                    try: pids.append(int(identifier))
                    except: pass
            
            if pids:
                self.flag_suspicious_processes(pids)

    def flag_by_offset_or_pid(self, identifier):
        identifier = str(identifier).lower().strip()
        found_any = False
        
        def _check_node(item):
            nonlocal found_any
            vals = self.proc_tree.item(item, 'values')
            if not vals: return
            
            # Check Offset (0) or PID (1)
            offset = str(vals[0]).lower().strip()
            pid = str(vals[1]).lower().strip()
            
            if identifier == offset or identifier == pid:
                self.proc_tree.item(item, tags=("suspicious",))
                curr_text = self.proc_tree.item(item, 'text')
                if "⚠️ " not in curr_text:
                    self.proc_tree.item(item, text="⚠️ " + curr_text)
                self._flag_descendants_warning(item)
                
                # Expand parent
                parent = self.proc_tree.parent(item)
                while parent:
                    self.proc_tree.item(parent, open=True)
                    parent = self.proc_tree.parent(parent)
                found_any = True
                
            for child in self.proc_tree.get_children(item):
                _check_node(child)

        for root_item in self.proc_tree.get_children():
            _check_node(root_item)
        
        if found_any:
            self.update_status(f"⚠️ Flagged suspicious item by ID/Offset: {identifier}")

class HexViewer:
    def __init__(self, parent, file_path, colors):
        self.root = tk.Toplevel(parent)
        self.file_path = file_path
        self.colors = colors
        self.page_size = 1024 * 16 # 16KB per page for smooth scrolling
        self.current_offset = 0
        
        self.root.title(f"Hex Viewer - {os.path.basename(file_path)}")
        self.root.geometry("900x600")
        self.root.configure(bg=colors["bg"])
        
        # UI
        toolbar = tk.Frame(self.root, bg=colors["header"], pady=5)
        toolbar.pack(fill="x")
        
        tk.Label(toolbar, text=f"File: {os.path.basename(file_path)}", fg="white", bg=colors["header"], font=("Segoe UI", 9, "bold")).pack(side="left", padx=10)
        
        self.file_size = os.path.getsize(file_path)
        tk.Label(toolbar, text=f"Size: {self.file_size / (1024*1024):.2f} MB", fg=colors["text_dim"], bg=colors["header"], font=("Segoe UI", 9)).pack(side="left")

        # Controls
        ctrl_frame = tk.Frame(toolbar, bg=colors["header"])
        ctrl_frame.pack(side="right", padx=10)
        
        tk.Button(ctrl_frame, text="◀ Prev", command=self.prev_page, bg=colors["accent"], fg="white", relief="flat", font=("Segoe UI", 8)).pack(side="left", padx=2)
        tk.Button(ctrl_frame, text="Next ▶", command=self.next_page, bg=colors["accent"], fg="white", relief="flat", font=("Segoe UI", 8)).pack(side="left", padx=2)
        
        # Main Viewer Area
        self.txt = tk.Text(self.root, bg=colors["bg_pane"], fg=colors["text"], font=("Consolas", 10), wrap="none", undo=False, borderwidth=0)
        self.txt.pack(fill="both", expand=True, padx=5, pady=5)
        
        sb = ttk.Scrollbar(self.root, orient="vertical", command=self.txt.yview)
        sb.pack(side="right", fill="y")
        self.txt.config(yscrollcommand=sb.set)
        
        self.render_hex()

    def render_hex(self):
        self.txt.config(state="normal")
        self.txt.delete("1.0", tk.END)
        
        try:
            with open(self.file_path, "rb") as f:
                f.seek(self.current_offset)
                chunk = f.read(self.page_size)
                
                lines = []
                for i in range(0, len(chunk), 16):
                    line_bytes = chunk[i:i+16]
                    offset = self.current_offset + i
                    
                    # Offset
                    off_str = f"{offset:08X}"
                    
                    # Hex
                    hex_str = " ".join(f"{b:02X}" for b in line_bytes)
                    hex_str = hex_str.ljust(47)
                    
                    # ASCII
                    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in line_bytes)
                    
                    lines.append(f"{off_str}  {hex_str}  |{ascii_str}|")
                
                self.txt.insert("1.0", "\n".join(lines))
        except Exception as e:
            self.txt.insert("1.0", f"Error reading file: {e}")
            
        self.txt.config(state="disabled")

    def next_page(self):
        if self.current_offset + self.page_size < self.file_size:
            self.current_offset += self.page_size
            self.render_hex()

    def prev_page(self):
        if self.current_offset > 0:
            self.current_offset = max(0, self.current_offset - self.page_size)
            self.render_hex()

if __name__ == "__main__":
    root = tk.Tk(); app = ForensicExperienceApp(root); root.mainloop()
