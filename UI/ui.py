import os
import sys
import threading
import queue
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

        self.title("SIH SanitizerOS — Storage Forensics, Recovery & Secure Sanitization")
        self.geometry("1080x740")
        self.minsize(880, 600)
        self.configure(bg="#008080")

        # Thread-safe UI update queue
        self.ui_queue = queue.Queue()
        self.after(50, self._process_ui_queue)

        # Cache of detected drives
        self.detected_drives = []

        self._build_ui()
        self.refresh_drives()

    # -------------------------------------------------------------
    # THREAD-SAFE UI DISPATCHER
    # -------------------------------------------------------------
    def dispatch_ui(self, func, *args, **kwargs):
        """Places a callable onto the queue to be executed on the main Tkinter thread."""
        self.ui_queue.put((func, args, kwargs))

    def _process_ui_queue(self):
        """Periodically runs on the main thread and drains pending UI updates."""
        while not self.ui_queue.empty():
            try:
                func, args, kwargs = self.ui_queue.get_nowait()
                func(*args, **kwargs)
            except queue.Empty:
                break
            except Exception as e:
                print(f"[UI Dispatch Error] {e}", file=sys.stderr)
        self.after(50, self._process_ui_queue)

    # -------------------------------------------------------------
    # UI CONSTRUCTION
    # -------------------------------------------------------------
    def _build_ui(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure(".", font=("MS Sans Serif", 9), background="#D4D0C8")
        self.style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF", font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("MS Sans Serif", 9, "bold"), background="#D4D0C8")
        self.style.configure("TNotebook", background="#D4D0C8")
        self.style.configure("TNotebook.Tab", font=("MS Sans Serif", 9, "bold"), padding=[12, 4])

        window_frame = tk.Frame(self, bg="#D4D0C8", bd=3, relief="raised")
        window_frame.pack(fill="both", expand=True, padx=8, pady=8)

        # Top Banner
        banner_frame = tk.Frame(window_frame, bg="#000080", bd=2, relief="sunken")
        banner_frame.pack(fill="x", padx=6, pady=(6, 4))
        banner_title = tk.Label(
            banner_frame,
            text="SIH SanitizerOS Forensic Console (NIST SP 800-88 / libtsk Carving / SHA-256)",
            bg="#000080",
            fg="#FFFFFF",
            font=("Segoe UI", 10, "bold")
        )
        banner_title.pack(side="left", padx=8, pady=5)

        # Notebook tabs
        self.notebook = ttk.Notebook(window_frame)
        self.notebook.pack(fill="both", expand=True, padx=6, pady=4)

        # TAB 1: Storage Drives & Sanitization
        self.tab_devices = tk.Frame(self.notebook, bg="#D4D0C8")
        self.notebook.add(self.tab_devices, text=" 💾 Storage Drives & Sanitization ")
        self._build_device_tab()

        # TAB 2: Forensic Disk Acquisition (NEW)
        self.tab_acquisition = tk.Frame(self.notebook, bg="#D4D0C8")
        self.notebook.add(self.tab_acquisition, text=" 📷 Forensic Acquisition ")
        self._build_acquisition_tab()

        # TAB 3: Data Recovery & Carving
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
            self.append_log(f"[CRITICAL ERROR] Native C++ module not found ({IMPORT_ERR}). No hardware operations can be performed.")

    # -------------------------------------------------------------
    # TAB 1: STORAGE DRIVES & SANITIZATION
    # -------------------------------------------------------------
    def _build_device_tab(self):
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

        table_frame = tk.Frame(self.tab_devices, bd=2, relief="sunken")
        table_frame.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("device", "model", "serial", "capacity", "bus", "media", "safety", "protocol")
        self.drive_table = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        self.drive_table.heading("device", text="Device Path")
        self.drive_table.heading("model", text="Model")
        self.drive_table.heading("serial", text="Serial Number")
        self.drive_table.heading("capacity", text="Capacity")
        self.drive_table.heading("bus", text="Bus Type")
        self.drive_table.heading("media", text="Media")
        self.drive_table.heading("safety", text="Safety Status")
        self.drive_table.heading("protocol", text="Recommended Protocol")

        self.drive_table.column("device", width=110)
        self.drive_table.column("model", width=180)
        self.drive_table.column("serial", width=130)
        self.drive_table.column("capacity", width=90)
        self.drive_table.column("bus", width=70)
        self.drive_table.column("media", width=60)
        self.drive_table.column("safety", width=150)
        self.drive_table.column("protocol", width=220)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.drive_table.yview)
        self.drive_table.configure(yscrollcommand=scrollbar.set)
        self.drive_table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.drive_table.bind("<<TreeviewSelect>>", self._on_drive_selected)

    def refresh_drives(self):
        for item in self.drive_table.get_children():
            self.drive_table.delete(item)

        self.detected_drives = []

        if not CPP_SANITIZER_AVAILABLE:
            self.append_log("[ERROR] Unable to retrieve storage devices: C++ core module is not loaded.")
            return

        try:
            drives = cpp_sanitizer.get_drives()
            self.detected_drives = drives

            if not drives:
                self.append_log("[DEVICE SCAN] No storage devices found in /sys/block (Root privileges may be required).")
                return

            self.append_log(f"[DEVICE SCAN] Discovered {len(drives)} physical storage device(s).")
            for drv in drives:
                dev = drv.get("device", "")
                proto_info = cpp_sanitizer.get_sanitization_info(dev)
                rec_proto = proto_info.get("recommended_protocol", "Standard Overwrite")
                cap_str = format_bytes(drv.get("capacity", 0))

                # System protection indicator
                is_sys = drv.get("is_system_disk", False)
                is_mnt = drv.get("is_mounted", False)
                if is_sys:
                    safety_str = "🔒 SYSTEM (Protected)"
                elif is_mnt:
                    mounts = drv.get("mount_points", [])
                    mnt_short = mounts[0] if mounts else "mounted"
                    safety_str = f"⚠️ Mounted ({mnt_short})"
                else:
                    safety_str = "✅ SAFE (Unmounted)"

                self.drive_table.insert("", "end", values=(
                    dev,
                    drv.get("model", "Generic Drive"),
                    drv.get("serial", "N/A"),
                    cap_str,
                    drv.get("bus", "UNKNOWN"),
                    drv.get("media_type", "UNKNOWN"),
                    safety_str,
                    rec_proto
                ))

            # Update acquisition source dropdown
            self._update_acquisition_device_list()

        except Exception as e:
            self.append_log(f"[ERROR] Failed to query storage devices from C++ core: {e}")

    def _on_drive_selected(self, event):
        selected = self.drive_table.selection()
        if not selected:
            return
        vals = self.drive_table.item(selected[0], "values")
        if vals:
            self.append_log(f"[SELECTED DRIVE] {vals[0]} ({vals[1]}, {vals[3]}) — Safety: {vals[6]}")

    def show_drive_info(self):
        selected = self.drive_table.selection()
        if not selected:
            messagebox.showinfo("Drive Info", "Please select a drive from the table first.")
            return

        dev_path = self.drive_table.item(selected[0], "values")[0]
        if not CPP_SANITIZER_AVAILABLE:
            messagebox.showerror("Error", "C++ core module is not loaded.")
            return

        try:
            info = cpp_sanitizer.get_drive_info(dev_path)
            proto = cpp_sanitizer.get_sanitization_info(dev_path)

            mount_info = ", ".join(info.get("mount_points", [])) if info.get("mount_points") else "None"
            msg = (
                f"Device Path: {info.get('device')}\n"
                f"Model: {info.get('model')}\n"
                f"Serial: {info.get('serial')}\n"
                f"Capacity: {format_bytes(info.get('capacity', 0))} ({info.get('capacity', 0)} bytes)\n"
                f"Bus Type: {info.get('bus')}\n"
                f"Media: {info.get('media_type')}\n"
                f"Sector Sizes: {info.get('logical_sector_size')} B (Logical) / {info.get('physical_sector_size')} B (Physical)\n"
                f"Rotational: {'Yes (Platter)' if info.get('rotational') else 'No (Solid State)'}\n"
                f"System Disk: {'YES (Protected)' if info.get('is_system_disk') else 'No'}\n"
                f"Active Mounts: {mount_info}\n\n"
                f"Recommended Protocol: {proto.get('recommended_protocol')}\n"
                f"Standard: {proto.get('standard')}\n"
                f"Description: {proto.get('description')}\n"
                f"Safety Policy: {proto.get('safety_status')}"
            )
            messagebox.showinfo(f"Drive Details — {dev_path}", msg)
        except Exception as e:
            self.append_log(f"[ERROR] get_drive_info failed: {e}")
            messagebox.showerror("Error", f"Failed to get drive info: {e}")

    def confirm_and_sanitize(self):
        selected = self.drive_table.selection()
        if not selected:
            messagebox.showwarning("Sanitization", "Please select a target drive to sanitize.")
            return

        vals = self.drive_table.item(selected[0], "values")
        target_path = vals[0]
        target_model = vals[1]
        safety_status = vals[6]

        # 1. CRITICAL SAFETY CHECK: System Disk Protection
        if "SYSTEM" in safety_status:
            messagebox.showerror(
                "CRITICAL SAFETY BLOCK",
                f"Target {target_path} is an ACTIVE HOST SYSTEM DISK.\n\n"
                f"Sanitization is strictly blocked by SIH SanitizerOS safety policy "
                f"to prevent destructive operating system erasure.",
                icon="error"
            )
            self.append_log(f"🛑 [SAFETY BLOCK] Sanitization aborted: {target_path} is a protected system disk.")
            return

        if "Mounted" in safety_status:
            messagebox.showwarning(
                "MOUNTED PARTITION WARNING",
                f"Target {target_path} contains active mounted partitions.\n\n"
                f"Please unmount all partitions before attempting sanitization to avoid file system corruption.",
                icon="warning"
            )
            self.append_log(f"⚠️ [SAFETY BLOCK] Sanitization aborted: {target_path} has active mounts.")
            return

        # 2. Confirmation Dialog
        confirm = messagebox.askyesno(
            "⚠️ PERMANENT DATA DESTRUCTION WARNING",
            f"Are you absolutely sure you want to sanitize:\n\n"
            f"  Device: {target_path}\n"
            f"  Model:  {target_model}\n\n"
            f"This will PERMANENTLY erase all user data and partition tables.\n"
            f"This action CANNOT be undone!\n\n"
            f"Proceed with sanitization?",
            icon="warning"
        )
        if not confirm:
            self.append_log("[CANCELLED] Sanitization cancelled by operator.")
            return

        threading.Thread(target=self._worker_sanitize, args=(target_path,), daemon=True).start()

    def show_audit_certificate(self, res):
        top = tk.Toplevel(self)
        top.title("NIST SP 800-88 Rev 1 Certificate of Sanitization")
        top.geometry("660x580")
        top.transient(self)
        top.grab_set()
        top.configure(bg="#D4D0C8")

        assurance = res.get("assurance_level", "NONE")
        success = res.get("success", False)

        bg_color = "#006600" if (success and assurance == "PURGE") else ("#008080" if success else "#990000")
        title_text = f"NIST SP 800-88 Rev 1 — SANITIZATION CERTIFICATE [{assurance}]"

        banner = tk.Frame(top, bg=bg_color, bd=2, relief="raised")
        banner.pack(fill="x", padx=10, pady=10)

        lbl_title = tk.Label(banner, text=title_text, bg=bg_color, fg="#FFFFFF", font=("Segoe UI", 11, "bold"))
        lbl_title.pack(padx=10, pady=8)

        text_frame = tk.Frame(top, bg="#D4D0C8")
        text_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        txt = tk.Text(text_frame, bg="#FFFFFF", fg="#000000", font=("Consolas", 9), relief="sunken")
        txt.pack(fill="both", expand=True)

        target = res.get("target_device", "Unknown")
        method = res.get("method_applied", "Unknown")
        media = res.get("media_type", "Unknown")
        duration = res.get("duration_seconds", 0.0)
        bytes_proc = res.get("bytes_processed", 0)
        cap_bytes = res.get("capacity_bytes", 0)
        samples = res.get("samples_checked", 0)
        ver_method = res.get("verification_method", "Unknown")
        started = res.get("started_at_utc", "N/A")
        completed = res.get("completed_at_utc", "N/A")
        wipe_pass = "PASSED" if res.get("wipe_passed") else "FAILED"
        ver_pass = "PASSED" if res.get("verification_passed") else "FAILED"
        error_msg = res.get("error", "None")
        if not error_msg:
            error_msg = "None"

        report = (
            "======================================================================\n"
            "                 OFFICIAL SANITIZATION AUDIT RECORD                    \n"
            "                     NIST SP 800-88 Rev 1 Guidelines                  \n"
            "======================================================================\n\n"
            f"OVERALL STATUS:       {'SUCCESSFUL' if success else 'FAILED'}\n"
            f"ASSURANCE LEVEL:      {assurance} (NIST SP 800-88 Rev 1)\n"
            f"TARGET DEVICE:        {target}\n"
            f"MEDIA TYPE:           {media}\n"
            f"DEVICE CAPACITY:      {format_bytes(cap_bytes)} ({cap_bytes:,} bytes)\n"
            f"BYTES PROCESSED:      {format_bytes(bytes_proc)} ({bytes_proc:,} bytes)\n\n"
            f"METHOD APPLIED:       {method}\n"
            f"WIPE STATUS:          {wipe_pass}\n"
            f"VERIFICATION STATUS:  {ver_pass}\n"
            f"VERIFICATION METHOD:  {ver_method}\n"
            f"SAMPLES CHECKED:      {samples} surface blocks\n\n"
            f"TIMESTAMPS (UTC):\n"
            f"  Started:            {started}\n"
            f"  Completed:          {completed}\n"
            f"  Elapsed Duration:   {duration:.2f} seconds\n\n"
            f"ERROR LOG:            {error_msg}\n"
            "======================================================================\n"
            "This record certifies that the indicated storage device was subjected\n"
            "to sanitization in compliance with NIST SP 800-88 Rev 1 protocols.\n"
            "======================================================================\n"
        )

        txt.insert("end", report)
        txt.configure(state="disabled")

        btn_close = tk.Button(top, text="Close Certificate", font=("MS Sans Serif", 9, "bold"), bg="#D4D0C8", command=top.destroy)
        btn_close.pack(pady=(0, 10))

    def _worker_sanitize(self, target_path):
        self.dispatch_ui(self.set_progress, 20)
        self.dispatch_ui(self.append_log, f"[SANITIZATION START] Initializing capability probe on '{target_path}'...")

        if not CPP_SANITIZER_AVAILABLE:
            self.dispatch_ui(self.set_progress, 0)
            self.dispatch_ui(self.append_log, "[ERROR] C++ Sanitizer module not available.")
            return

        try:
            self.dispatch_ui(self.set_progress, 40)
            self.dispatch_ui(self.append_log, f"[SANITIZATION] Executing hardware wipe pipeline...")

            res = cpp_sanitizer.sanitize_drive(target_path)

            if res.get("blocked", False):
                self.dispatch_ui(self.set_progress, 0)
                self.dispatch_ui(self.append_log, f"🛑 [BLOCKED] {res.get('error')}")
                self.dispatch_ui(messagebox.showerror, "Sanitization Blocked", res.get("error"))
                return

            assurance = res.get("assurance_level", "NONE")
            method = res.get("method_applied", "Unknown")
            duration = res.get("duration_seconds", 0.0)
            samples = res.get("samples_checked", 0)
            success = res.get("success", False)

            if success:
                self.dispatch_ui(self.set_progress, 100)
                log_msg = (
                    f"✅ [SUCCESS] Drive '{target_path}' sanitized via '{method}'.\n"
                    f"   NIST Assurance: {assurance} | Duration: {duration:.2f}s | Verification: Passed ({samples} samples checked)."
                )
                self.dispatch_ui(self.append_log, log_msg)
                self.dispatch_ui(self.show_audit_certificate, res)
            else:
                self.dispatch_ui(self.set_progress, 0)
                err = res.get("error", "Unknown error")
                self.dispatch_ui(self.append_log, f"❌ [FAILURE] Sanitization failed: {err}")
                self.dispatch_ui(self.show_audit_certificate, res)

        except Exception as e:
            self.dispatch_ui(self.set_progress, 0)
            self.dispatch_ui(self.append_log, f"[EXCEPTION] Sanitization runtime error: {e}")

    # -------------------------------------------------------------
    # TAB 2: FORENSIC ACQUISITION (NEW)
    # -------------------------------------------------------------
    def _build_acquisition_tab(self):
        container = tk.Frame(self.tab_acquisition, bg="#D4D0C8")
        container.pack(fill="both", expand=True, padx=12, pady=10)

        # Form Frame
        form_frame = tk.LabelFrame(container, text=" Acquisition Parameters ", bg="#D4D0C8", font=("MS Sans Serif", 9, "bold"))
        form_frame.pack(fill="x", padx=6, pady=6)

        # Source device selection
        row1 = tk.Frame(form_frame, bg="#D4D0C8")
        row1.pack(fill="x", padx=10, pady=8)
        lbl_src = tk.Label(row1, text="Source Storage Device:", width=22, anchor="w", bg="#D4D0C8", font=("MS Sans Serif", 9, "bold"))
        lbl_src.pack(side="left")

        self.acq_device_var = tk.StringVar(value="")
        self.combo_acq_device = ttk.Combobox(row1, textvariable=self.acq_device_var, state="readonly", width=40)
        self.combo_acq_device.pack(side="left", padx=6)

        # Output image path selection
        row2 = tk.Frame(form_frame, bg="#D4D0C8")
        row2.pack(fill="x", padx=10, pady=8)
        lbl_out = tk.Label(row2, text="Destination Image File:", width=22, anchor="w", bg="#D4D0C8", font=("MS Sans Serif", 9, "bold"))
        lbl_out.pack(side="left")

        self.acq_output_var = tk.StringVar(value="")
        entry_out = tk.Entry(row2, textvariable=self.acq_output_var, width=45)
        entry_out.pack(side="left", padx=6)

        btn_browse_acq = tk.Button(row2, text="Browse...", bg="#D4D0C8", relief="raised", command=self.browse_acquisition_output)
        btn_browse_acq.pack(side="left", padx=4)

        # Action button
        row3 = tk.Frame(form_frame, bg="#D4D0C8")
        row3.pack(fill="x", padx=10, pady=10)

        btn_start_acq = tk.Button(
            row3,
            text="🔒 Start Forensic Acquisition (Write-Block & SHA-256)",
            font=("MS Sans Serif", 9, "bold"),
            bg="#D4D0C8",
            fg="#000080",
            relief="raised",
            command=self.start_acquisition
        )
        btn_start_acq.pack(side="left")

        # Evidence Manifest Display
        manifest_frame = tk.LabelFrame(container, text=" Evidence Manifest & Cryptographic Record ", bg="#D4D0C8", font=("MS Sans Serif", 9, "bold"))
        manifest_frame.pack(fill="both", expand=True, padx=6, pady=6)

        self.manifest_text = tk.Text(manifest_frame, bg="#FFFFFF", fg="#000000", font=("Consolas", 9), relief="sunken")
        self.manifest_text.pack(fill="both", expand=True, padx=6, pady=6)
        self.manifest_text.insert("end", "Evidence records and SHA-256 verification will appear here upon acquisition completion.\n")

    def _update_acquisition_device_list(self):
        device_paths = [drv.get("device", "") for drv in self.detected_drives if drv.get("device")]
        self.combo_acq_device["values"] = device_paths
        if device_paths and not self.acq_device_var.get():
            self.acq_device_var.set(device_paths[0])

    def browse_acquisition_output(self):
        dest_file = filedialog.asksaveasfilename(
            title="Save Forensic Image Destination",
            defaultextension=".dd",
            filetypes=[("Raw Forensic Image (*.dd)", "*.dd"), ("Disk Image (*.raw)", "*.raw"), ("All Files", "*.*")]
        )
        if dest_file:
            self.acq_output_var.set(dest_file)

    def start_acquisition(self):
        src_dev = self.acq_device_var.get().strip()
        dst_img = self.acq_output_var.get().strip()

        if not src_dev:
            messagebox.showwarning("Acquisition", "Please select a source storage device.")
            return

        if not dst_img:
            messagebox.showwarning("Acquisition", "Please choose a destination file path for the forensic image.")
            return

        if not CPP_SANITIZER_AVAILABLE:
            messagebox.showerror("Error", "C++ core module is not loaded.")
            return

        confirm = messagebox.askyesno(
            "Confirm Forensic Acquisition",
            f"Start write-blocked forensic bit-stream acquisition?\n\n"
            f"Source:      {src_dev}\n"
            f"Destination: {dst_img}\n\n"
            f"This process will compute a cryptographic SHA-256 digest on the fly.",
            icon="question"
        )
        if not confirm:
            return

        threading.Thread(target=self._worker_acquisition, args=(src_dev, dst_img), daemon=True).start()

    def _worker_acquisition(self, src_dev, dst_img):
        self.dispatch_ui(self.set_progress, 15)
        self.dispatch_ui(self.append_log, f"[ACQUISITION] Enforcing write-block on '{src_dev}' and starting image capture...")

        try:
            res = cpp_sanitizer.acquire_image(src_dev, dst_img)

            if res.get("success", False):
                self.dispatch_ui(self.set_progress, 100)
                sha = res.get("sha256", "N/A")
                size = res.get("size_bytes", 0)
                ts = res.get("acquired_at_utc", "N/A")
                mdl = res.get("source_model", "Unknown")
                ser = res.get("source_serial", "Unknown")

                manifest = (
                    f"======================================================================\n"
                    f"                     FORENSIC ACQUISITION RECORD                      \n"
                    f"======================================================================\n"
                    f"Timestamp (UTC):   {ts}\n"
                    f"Source Device:     {src_dev}\n"
                    f"Source Model:      {mdl}\n"
                    f"Source Serial:     {ser}\n"
                    f"Image Path:        {dst_img}\n"
                    f"Image Size:        {format_bytes(size)} ({size} bytes)\n"
                    f"SHA-256 Checksum:  {sha}\n"
                    f"Status:            VERIFIED & ACQUIRED (Read-Only Write-Blocked)\n"
                    f"======================================================================\n"
                )
                self.dispatch_ui(self._set_manifest_content, manifest)
                self.dispatch_ui(self.append_log, f"✅ [ACQUISITION COMPLETE] SHA-256: {sha}")
                self.dispatch_ui(messagebox.showinfo, "Acquisition Success", f"Image captured successfully!\n\nSHA-256: {sha}")
            else:
                self.dispatch_ui(self.set_progress, 0)
                err = res.get("error", "Unknown error")
                self.dispatch_ui(self.append_log, f"❌ [ACQUISITION FAILED] {err}")
                self.dispatch_ui(messagebox.showerror, "Acquisition Failed", f"Failed to acquire device: {err}")

        except Exception as e:
            self.dispatch_ui(self.set_progress, 0)
            self.dispatch_ui(self.append_log, f"[EXCEPTION] Acquisition runtime error: {e}")

    def _set_manifest_content(self, text):
        self.manifest_text.delete("1.0", "end")
        self.manifest_text.insert("end", text)

    # -------------------------------------------------------------
    # TAB 3: DATA RECOVERY & CARVING
    # -------------------------------------------------------------
    def _build_recovery_tab(self):
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
            filetypes=[("Forensic Disk Images", "*.dd *.raw *.img *.bin *.001"), ("All Files", "*.*")]
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

        if not CPP_SANITIZER_AVAILABLE:
            messagebox.showerror("Error", "C++ core module is not loaded.")
            return

        threading.Thread(target=self._worker_carving, args=(img_path,), daemon=True).start()

    def _worker_carving(self, img_path):
        self.dispatch_ui(self._clear_recovery_table)
        self.dispatch_ui(self.set_progress, 20)
        self.dispatch_ui(self.append_log, f"[CARVER] Scanning '{img_path}' with Sleuth Kit for JPEG, PDF, ZIP headers...")

        output_dir = os.path.join(os.getcwd(), "CASE_DATA")
        os.makedirs(output_dir, exist_ok=True)

        try:
            candidates = cpp_sanitizer.scan_image(img_path, output_dir)
            self.dispatch_ui(self.set_progress, 85)

            if not candidates:
                self.dispatch_ui(self.set_progress, 100)
                self.dispatch_ui(self.append_log, f"[CARVER] Scan finished: 0 file signatures found in '{img_path}'.")
                return

            self.dispatch_ui(self.append_log, f"[CARVER SUCCESS] Identified {len(candidates)} file candidate(s).")
            for c in candidates:
                self.dispatch_ui(
                    self.recovery_table.insert,
                    "",
                    "end",
                    values=(
                        c.get("file_type", "Unknown"),
                        hex(c.get("offset_start", 0)),
                        format_bytes(c.get("size", 0)),
                        c.get("confidence", "UNVERIFIED"),
                        c.get("validation", "UNVERIFIED"),
                        c.get("category", "Unknown"),
                        os.path.basename(c.get("output_path", "")) if c.get("output_path") else "(not saved)",
                        c.get("sha256", "N/A")
                    )
                )

            self.dispatch_ui(self.set_progress, 100)

        except Exception as e:
            self.dispatch_ui(self.set_progress, 0)
            self.dispatch_ui(self.append_log, f"[CARVER ERROR] Carving scan failed: {e}")

    def _clear_recovery_table(self):
        for item in self.recovery_table.get_children():
            self.recovery_table.delete(item)

    # -------------------------------------------------------------
    # CONSOLE & PROGRESS HELPERS
    # -------------------------------------------------------------
    def append_log(self, text):
        self.console.insert("end", f"> {text}\n")
        self.console.see("end")

    def set_progress(self, val):
        self.progress_bar['value'] = val


if __name__ == "__main__":
    app = SIHSanitizerExplorer()
    app.mainloop()