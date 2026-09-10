import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Import C++ sanitizer & forensic module built by CMake
try:
    import cpp_sanitizer
    CPP_SANITIZER_AVAILABLE = True
except ImportError as e:
    CPP_SANITIZER_AVAILABLE = False
    IMPORT_ERR = str(e)


def format_bytes(num_bytes):
    if num_bytes is None or num_bytes == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


class SIHSanitizerExplorer(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("SIH SanitizerOS — Forensic Recovery & Sanitization Explorer")
        self.geometry("1020x720")
        self.minsize(840, 560)
        self.configure(bg="#008080")

        # Native C++ DataSanitizer instance
        if CPP_SANITIZER_AVAILABLE:
            self.sanitizer = cpp_sanitizer.DataSanitizer()
        else:
            self.sanitizer = None

        self._build_ui()
        self.refresh_drives()

    def _build_ui(self):
        # Classic Retro Windows XP / Workstation Theme
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", font=("MS Sans Serif", 9), background="#D4D0C8")
        self.style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF", font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("MS Sans Serif", 9, "bold"), background="#D4D0C8")
        self.style.configure("TNotebook", background="#D4D0C8")
        self.style.configure("TNotebook.Tab", font=("MS Sans Serif", 9, "bold"), padding=[10, 4])

        window_frame = tk.Frame(self, bg="#D4D0C8", bd=3, relief="raised")
        window_frame.pack(fill="both", expand=True, padx=8, pady=8)

        # Title / Banner
        banner_frame = tk.Frame(window_frame, bg="#000080", bd=2, relief="sunken")
        banner_frame.pack(fill="x", padx=6, pady=(6, 4))
        banner_title = tk.Label(
            banner_frame,
            text="SIH SanitizerOS Forensic Console (NIST SP 800-88 / libtsk Carving)",
            bg="#000080",
            fg="#FFFFFF",
            font=("Segoe UI", 10, "bold")
        )
        banner_title.pack(side="left", padx=8, pady=4)

        # Tabbed Views
        self.notebook = ttk.Notebook(window_frame)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=4)

        # TAB 1: Storage Devices & Sanitization
        self.tab_devices = tk.Frame(self.notebook, bg="#D4D0C8")
        self.notebook.add(self.tab_devices, text=" 💾 Storage Drives & Sanitization ")
        self._build_device_tab()

        # TAB 2: Forensic Carving & Recovery
        self.tab_recovery = tk.Frame(self.notebook, bg="#D4D0C8")
        self.notebook.add(self.tab_recovery, text=" 🔍 Data Recovery & Carving ")
        self._build_recovery_tab()

        # Bottom Frame: Status, Progress Bar & System Log
        bottom_frame = tk.Frame(window_frame, bg="#D4D0C8")
        bottom_frame.pack(fill="both", expand=False, padx=6, pady=4)

        self.progress_bar = ttk.Progressbar(bottom_frame, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", pady=(2, 4))

        self.console = tk.Text(bottom_frame, bg="#000000", fg="#00FF66", font=("Consolas", 9), height=7)
        self.console.pack(fill="both", expand=True)

        if CPP_SANITIZER_AVAILABLE:
            self.append_log("[CORE LOADED] Native C++ SanitizerOS subsystem online via Pybind11.")
        else:
            self.append_log(f"[WARNING] Native C++ module not detected ({IMPORT_ERR}). Running in demo/emulation mode.")

    # -------------------------------------------------------------
    # TAB 1: STORAGE DRIVES & SANITIZATION
    # -------------------------------------------------------------
    def _build_device_tab(self):
        # Top toolbar
        toolbar = tk.Frame(self.tab_devices, bg="#D4D0C8")
        toolbar.pack(fill="x", padx=6, pady=6)

        btn_refresh = tk.Button(toolbar, text="🔄 Rescan Devices", font=("MS Sans Serif", 9),
                                bg="#D4D0C8", relief="raised", command=self.refresh_drives)
        btn_refresh.pack(side="left", padx=4)

        btn_inspect = tk.Button(toolbar, text="ℹ️ Inspect Drive Info", font=("MS Sans Serif", 9),
                                bg="#D4D0C8", relief="raised", command=self.show_drive_info)
        btn_inspect.pack(side="left", padx=4)

        btn_sanitize = tk.Button(toolbar, text="🛡️ Sanitize Target (NIST 800-88)", font=("MS Sans Serif", 9, "bold"),
                                 bg="#D4D0C8", fg="#990000", relief="raised", command=self.confirm_and_sanitize)
        btn_sanitize.pack(side="right", padx=4)

        # Drive table
        table_frame = tk.Frame(self.tab_devices, bd=2, relief="sunken")
        table_frame.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("device", "model", "serial", "capacity", "bus", "media", "status")
        self.drive_table = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.drive_table.heading("device", text="Device Path")
        self.drive_table.heading("model", text="Model")
        self.drive_table.heading("serial", text="Serial Number")
        self.drive_table.heading("capacity", text="Capacity")
        self.drive_table.heading("bus", text="Bus Type")
        self.drive_table.heading("media", text="Media Type")
        self.drive_table.heading("status", text="Recommended Sanitization")

        self.drive_table.column("device", width=120)
        self.drive_table.column("model", width=220)
        self.drive_table.column("serial", width=140)
        self.drive_table.column("capacity", width=100)
        self.drive_table.column("bus", width=80)
        self.drive_table.column("media", width=80)
        self.drive_table.column("status", width=240)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.drive_table.yview)
        self.drive_table.configure(yscrollcommand=scrollbar.set)
        self.drive_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.drive_table.bind("<<TreeviewSelect>>", self._on_drive_selected)

    def refresh_drives(self):
        for item in self.drive_table.get_children():
            self.drive_table.delete(item)

        if CPP_SANITIZER_AVAILABLE:
            try:
                drives = cpp_sanitizer.get_drives()
                self.append_log(f"[DEVICE SCAN] Discovered {len(drives)} storage device(s).")
                for drv in drives:
                    proto_info = cpp_sanitizer.get_sanitization_info(drv.get("device", ""))
                    rec_proto = proto_info.get("recommended_protocol", "Standard Overwrite")
                    cap_str = format_bytes(drv.get("capacity", 0))

                    self.drive_table.insert("", "end", values=(
                        drv.get("device", ""),
                        drv.get("model", "Generic Drive"),
                        drv.get("serial", "N/A"),
                        cap_str,
                        drv.get("bus", "UNKNOWN"),
                        drv.get("media_type", "UNKNOWN"),
                        rec_proto
                    ))
                return
            except Exception as e:
                self.append_log(f"[DEVICE ERROR] Failed to query drives via C++ core: {e}")

        # Fallback demonstration rows if no physical access / Windows demo
        sample_drives = [
            ("/dev/nvme0n1", "Samsung 980 PRO 1TB", "S5GXNF0R123456", 1000204886016, "NVME", "SSD", "NVMe Sanitize (NIST Purge)"),
            ("/dev/sda", "Crucial MX500 500GB", "1942E22199A1", 500107862016, "SATA", "SSD", "ATA Secure Erase (NIST Purge)"),
            ("/dev/sdb", "WDC WD20EZAZ 2TB", "WD-WCC4N7128912", 2000398934016, "SATA", "HDD", "DoD 5220.22-M 3-Pass (Clear)")
        ]
        for dev, mdl, ser, cap, bus, med, proto in sample_drives:
            self.drive_table.insert("", "end", values=(dev, mdl, ser, format_bytes(cap), bus, med, proto))
        self.append_log("[DEMO MODE] Loaded virtual device catalogue for inspection.")

    def _on_drive_selected(self, event):
        selected = self.drive_table.selection()
        if not selected:
            return
        vals = self.drive_table.item(selected[0], "values")
        if vals:
            self.append_log(f"[SELECTED DRIVE] {vals[0]} ({vals[1]}, {vals[3]}) — Protocol: {vals[6]}")

    def show_drive_info(self):
        selected = self.drive_table.selection()
        if not selected:
            messagebox.showinfo("Drive Info", "Please select a drive from the table first.")
            return

        dev_path = self.drive_table.item(selected[0], "values")[0]
        if CPP_SANITIZER_AVAILABLE:
            try:
                info = cpp_sanitizer.get_drive_info(dev_path)
                proto = cpp_sanitizer.get_sanitization_info(dev_path)
                msg = (
                    f"Device Path: {info.get('device')}\n"
                    f"Model: {info.get('model')}\n"
                    f"Serial: {info.get('serial')}\n"
                    f"Capacity: {format_bytes(info.get('capacity', 0))}\n"
                    f"Bus Type: {info.get('bus')}\n"
                    f"Media: {info.get('media_type')}\n"
                    f"Logical Sector: {info.get('logical_sector_size')} B\n"
                    f"Physical Sector: {info.get('physical_sector_size')} B\n\n"
                    f"Recommended Protocol: {proto.get('recommended_protocol')}\n"
                    f"Standard: {proto.get('standard')}\n"
                    f"Details: {proto.get('description')}"
                )
                messagebox.showinfo(f"Drive Details — {dev_path}", msg)
                return
            except Exception as e:
                self.append_log(f"[ERROR] get_drive_info failed: {e}")

        vals = self.drive_table.item(selected[0], "values")
        msg = f"Device: {vals[0]}\nModel: {vals[1]}\nSerial: {vals[2]}\nCapacity: {vals[3]}\nBus: {vals[4]}\nMedia: {vals[5]}\nRecommended: {vals[6]}"
        messagebox.showinfo(f"Drive Details — {vals[0]}", msg)

    def confirm_and_sanitize(self):
        selected = self.drive_table.selection()
        if not selected:
            messagebox.showwarning("Sanitization", "Please select a target drive to sanitize.")
            return

        target_path = self.drive_table.item(selected[0], "values")[0]
        target_model = self.drive_table.item(selected[0], "values")[1]

        # Critical confirmation modal
        confirm = messagebox.askyesno(
            "⚠️ PERMANENT DATA DESTRUCTION WARNING",
            f"Are you absolutely sure you want to sanitize:\n\n"
            f"  Target: {target_path} ({target_model})\n\n"
            f"This will PERMANENTLY erase all data on the target storage device.\n"
            f"This action CANNOT be undone!\n\n"
            f"Do you wish to proceed?",
            icon="warning"
        )
        if not confirm:
            self.append_log("[CANCELLED] Sanitization aborted by operator.")
            return

        threading.Thread(target=self._execute_sanitization, args=(target_path,), daemon=True).start()

    def _execute_sanitization(self, target_path):
        self.progress_bar['value'] = 10
        self.append_log(f"[SANITIZATION START] Initializing wipe engine on '{target_path}'...")

        if not CPP_SANITIZER_AVAILABLE or not self.sanitizer:
            time.sleep(1.2)
            self.progress_bar['value'] = 60
            time.sleep(1.0)
            self.progress_bar['value'] = 100
            self.append_log(f"[SIMULATION] Multi-pass wipe and zero-verification simulated on '{target_path}'.")
            return

        try:
            self.progress_bar['value'] = 30
            self.append_log(f"[SANITIZATION] Executing protocol passes on '{target_path}'...")
            success = self.sanitizer.sanitizeSector(target_path, 3)

            if success:
                self.progress_bar['value'] = 100
                self.append_log(f"✅ [SUCCESS] Target '{target_path}' sanitized and 100% zero-verified.")
                messagebox.showinfo("Sanitization Complete", f"Drive '{target_path}' has been securely sanitized and verified.")
            else:
                self.progress_bar['value'] = 0
                self.append_log(f"❌ [FAILURE] Sanitization failed for '{target_path}'. Check kernel permissions or lock state.")
                messagebox.showerror("Sanitization Failed", f"Failed to sanitize '{target_path}'.")
        except Exception as e:
            self.progress_bar['value'] = 0
            self.append_log(f"[EXCEPTION] Sanitization error: {e}")

    # -------------------------------------------------------------
    # TAB 2: FORENSIC RECOVERY & CARVING
    # -------------------------------------------------------------
    def _build_recovery_tab(self):
        # File selector toolbar
        toolbar = tk.Frame(self.tab_recovery, bg="#D4D0C8")
        toolbar.pack(fill="x", padx=6, pady=6)

        lbl_img = tk.Label(toolbar, text="Forensic Image:", bg="#D4D0C8", font=("MS Sans Serif", 9, "bold"))
        lbl_img.pack(side="left", padx=4)

        self.img_path_var = tk.StringVar(value="")
        entry_img = tk.Entry(toolbar, textvariable=self.img_path_var, width=45)
        entry_img.pack(side="left", padx=4)

        btn_browse = tk.Button(toolbar, text="📂 Browse Image...", bg="#D4D0C8", relief="raised", command=self.browse_image)
        btn_browse.pack(side="left", padx=4)

        btn_scan = tk.Button(toolbar, text="🔎 Carve Files (TSK Engine)", bg="#D4D0C8", font=("MS Sans Serif", 9, "bold"),
                             fg="#000080", relief="raised", command=self.start_carving_scan)
        btn_scan.pack(side="right", padx=4)

        # Carved files table
        table_frame = tk.Frame(self.tab_recovery, bd=2, relief="sunken")
        table_frame.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("type", "offset_start", "size", "confidence", "validation", "category", "output", "sha256")
        self.recovery_table = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="extended")
        self.recovery_table.heading("type", text="File Type")
        self.recovery_table.heading("offset_start", text="Byte Offset")
        self.recovery_table.heading("size", text="Carved Size")
        self.recovery_table.heading("confidence", text="Confidence")
        self.recovery_table.heading("validation", text="Validation")
        self.recovery_table.heading("category", text="Category")
        self.recovery_table.heading("output", text="Saved File")
        self.recovery_table.heading("sha256", text="SHA-256 Hash")

        self.recovery_table.column("type", width=90)
        self.recovery_table.column("offset_start", width=110)
        self.recovery_table.column("size", width=90)
        self.recovery_table.column("confidence", width=100)
        self.recovery_table.column("validation", width=100)
        self.recovery_table.column("category", width=100)
        self.recovery_table.column("output", width=160)
        self.recovery_table.column("sha256", width=220)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.recovery_table.yview)
        self.recovery_table.configure(yscrollcommand=scrollbar.set)
        self.recovery_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def browse_image(self):
        file_selected = filedialog.askopenfilename(
            title="Select Forensic Disk Image",
            filetypes=[("Disk Images", "*.dd *.raw *.img *.bin *.001"), ("All Files", "*.*")]
        )
        if file_selected:
            self.img_path_var.set(file_selected)
            self.append_log(f"[IMAGE LOADED] Target forensic image: {file_selected}")

    def start_carving_scan(self):
        img_path = self.img_path_var.get().strip()
        if not img_path:
            messagebox.showwarning("File Carving", "Please select or enter a forensic image file path.")
            return

        if not os.path.exists(img_path):
            messagebox.showerror("Error", f"Image file does not exist: {img_path}")
            return

        threading.Thread(target=self._execute_carving, args=(img_path,), daemon=True).start()

    def _execute_carving(self, img_path):
        for item in self.recovery_table.get_children():
            self.recovery_table.delete(item)

        self.progress_bar['value'] = 15
        self.append_log(f"[CARVER] Scanning image '{img_path}' for forensic signatures (JPEG, PDF, ZIP)...")

        output_dir = os.path.join(os.getcwd(), "CASE_DATA")
        os.makedirs(output_dir, exist_ok=True)

        if CPP_SANITIZER_AVAILABLE:
            try:
                candidates = cpp_sanitizer.scan_image(img_path, output_dir)
                self.progress_bar['value'] = 80
                self.append_log(f"[CARVER COMPLETED] Sleuth Kit pipeline identified {len(candidates)} candidate(s).")

                for c in candidates:
                    self.recovery_table.insert("", "end", values=(
                        c.get("file_type", "Unknown"),
                        hex(c.get("offset_start", 0)),
                        format_bytes(c.get("size", 0)),
                        c.get("confidence", "UNVERIFIED"),
                        c.get("validation", "UNVERIFIED"),
                        c.get("category", "Unknown"),
                        os.path.basename(c.get("output_path", "")) if c.get("output_path") else "(not saved)",
                        c.get("sha256", "N/A")
                    ))
                self.progress_bar['value'] = 100
                return
            except Exception as e:
                self.append_log(f"[CARVER ERROR] Failed to run C++ carving pipeline: {e}")

        # Fallback demonstration rows
        self.progress_bar['value'] = 100
        self.append_log("[DEMO CARVER] Carving simulation finished.")

    def append_log(self, text):
        self.console.insert("end", f"> {text}\n")
        self.console.see("end")


if __name__ == "__main__":
    app = SIHSanitizerExplorer()
    app.mainloop()