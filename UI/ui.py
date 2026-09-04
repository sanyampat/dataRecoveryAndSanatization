import os

import threading

import tkinter as tk

from tkinter import ttk
 
# Import only the sanitisation binary built by CMake

try:

    import cpp_sanitizer

    CPP_SANITIZER_AVAILABLE = True

except ImportError as e:

    CPP_SANITIZER_AVAILABLE = False

    IMPORT_ERR = str(e)
 
 
class WindowsXPExplorer(tk.Tk):

    def __init__(self):

        super().__init__()
 
        self.title("Data Recovery & Sanitization Explorer (Windows XP)")

        self.geometry("920x640")

        self.configure(bg="#008080")
 
        # Connect C++ DataSanitizer class

        if CPP_SANITIZER_AVAILABLE:

            self.sanitizer = cpp_sanitizer.DataSanitizer()

        else:

            self.sanitizer = None
 
        self._build_ui()
 
    def _build_ui(self):

        # Apply Classic Retro Windows XP Styles

        self.style = ttk.Style()

        self.style.theme_use("clam")

        self.style.configure(".", font=("MS Sans Serif", 9), background="#D4D0C8")

        self.style.configure("Treeview", background="#FFFFFF", fieldbackground="#FFFFFF")
 
        window_frame = tk.Frame(self, bg="#D4D0C8", bd=3, relief="raised")

        window_frame.pack(fill="both", expand=True, padx=12, pady=12)
 
        # 1. Selection Options Control Panel

        options_frame = tk.LabelFrame(window_frame, text=" Selection Controls ", bg="#D4D0C8", font=("MS Sans Serif", 8, "bold"))

        options_frame.pack(fill="x", padx=8, pady=5)
 
        self.select_mode_var = tk.StringVar(value="single")
 
        rb_single = tk.Radiobutton(

            options_frame, text="Single Select Mode", variable=self.select_mode_var,

            value="single", bg="#D4D0C8", command=self._update_select_mode

        )

        rb_single.pack(side="left", padx=10, pady=5)
 
        rb_multi = tk.Radiobutton(

            options_frame, text="Multi-Select Mode", variable=self.select_mode_var,

            value="multi", bg="#D4D0C8", command=self._update_select_mode

        )

        rb_multi.pack(side="left", padx=10, pady=5)
 
        btn_select_all = tk.Button(options_frame, text="Select All Files", command=self.select_all_files, bg="#D4D0C8", relief="raised")

        btn_select_all.pack(side="right", padx=10, pady=5)
 
        # 2. File Explorer Table View

        file_list_frame = tk.Frame(window_frame, bd=2, relief="sunken")

        file_list_frame.pack(fill="both", expand=True, padx=8, pady=5)
 
        columns = ("path", "size", "status")

        self.file_table = ttk.Treeview(file_list_frame, columns=columns, show="headings", selectmode="browse")

        self.file_table.heading("path", text="Target Sector / File Path")

        self.file_table.heading("size", text="Size")

        self.file_table.heading("status", text="Status")
 
        self.file_table.column("path", width=340)

        self.file_table.column("size", width=100)

        self.file_table.column("status", width=220)
 
        # Populate initial target rows

        self.file_table.insert("", "end", values=("sector_001.bin", "512 B", "⚠️ Deleted"))

        self.file_table.insert("", "end", values=("orphaned_data.raw", "4096 B", "🟢 High Recoverability"))

        self.file_table.insert("", "end", values=("classified_log.txt", "1024 B", "🔒 Ready for Wiping"))
 
        self.file_table.pack(fill="both", expand=True)
 
        # 3. Action Buttons (Both Features Preserved)

        action_frame = tk.LabelFrame(window_frame, text=" Operations ", bg="#D4D0C8", font=("MS Sans Serif", 8, "bold"))

        action_frame.pack(fill="x", padx=8, pady=5)
 
        btn_recover = tk.Button(

            action_frame, text="🔍 Execute Recovery", font=("MS Sans Serif", 9, "bold"),

            bg="#D4D0C8", relief="raised", command=lambda: self.run_task("Recover")

        )

        btn_recover.pack(side="left", fill="x", expand=True, padx=6, pady=6)
 
        btn_sanitize = tk.Button(

            action_frame, text="🛡️ Sanitize Target (C++ Engine)", font=("MS Sans Serif", 9, "bold"),

            bg="#D4D0C8", relief="raised", command=lambda: self.run_task("Sanitize")

        )

        btn_sanitize.pack(side="left", fill="x", expand=True, padx=6, pady=6)
 
        # 4. Console Log & Progress Bar

        log_container = tk.Frame(window_frame, bg="#D4D0C8")

        log_container.pack(fill="both", expand=True, padx=8, pady=5)
 
        self.progress_bar = ttk.Progressbar(log_container, orient="horizontal", mode="determinate")

        self.progress_bar.pack(fill="x", pady=(2, 5))
 
        self.console = tk.Text(log_container, bg="#000000", fg="#00FF00", font=("Consolas", 9), height=7)

        self.console.pack(fill="both", expand=True)
 
        if CPP_SANITIZER_AVAILABLE:

            self.append_log("[SYSTEM READY] Native C++ DataSanitizer bound via Pybind11.")

        else:

            self.append_log(f"[ERROR] Could not import `cpp_sanitizer`: {IMPORT_ERR}")
 
    def _update_select_mode(self):

        mode = "extended" if self.select_mode_var.get() == "multi" else "browse"

        self.file_table.configure(selectmode=mode)

        self.append_log(f"Selection mode set to: {self.select_mode_var.get().upper()}")
 
    def select_all_files(self):

        self.select_mode_var.set("multi")

        self.file_table.configure(selectmode="extended")

        children = self.file_table.get_children()

        self.file_table.selection_set(children)

        self.append_log(f"Selected all {len(children)} items.")
 
    def append_log(self, text):

        self.console.insert("end", f"> {text}\n")

        self.console.see("end")
 
    def run_task(self, mode):

        selected = self.file_table.selection()

        if not selected:

            self.append_log(f"[{mode.upper()} ERROR] Please select a target row first.")

            return
 
        threading.Thread(target=self._execute_task_worker, args=(mode, selected), daemon=True).start()
 
    def _execute_task_worker(self, mode, selected):

        self.progress_bar['value'] = 0
 
        for idx, item in enumerate(selected):

            item_data = self.file_table.item(item)

            target_path = item_data["values"][0]
 
            if mode == "Sanitize":

                if not CPP_SANITIZER_AVAILABLE:

                    self.append_log("[ERROR] Cannot execute. C++ module not loaded.")

                    return
 
                self.append_log(f"[C++ CALL] Invoking `sanitizer.sanitizeSector('{target_path}', 3)`...")

                # Execute native C++ Sanitizer engine call

                success = self.sanitizer.sanitizeSector(target_path, 3)
 
                if success:

                    self.file_table.item(item, values=(target_path, item_data["values"][1], "✅ Sanitized"))

                    self.append_log(f"[SUCCESS] '{target_path}' successfully sanitized.")

                else:

                    self.file_table.item(item, values=(target_path, item_data["values"][1], "❌ Sanitization Failed"))

                    self.append_log(f"[ERROR] Sanitization failed for '{target_path}'.")
 
            elif mode == "Recover":

                # Pending module update logic

                self.append_log(f"[RECOVERY STUB] Target '{target_path}' selected. C++ Recovery module update pending.")
 
            self.progress_bar['value'] = int(((idx + 1) / len(selected)) * 100)
 
        self.append_log(f"[{mode.upper()} COMPLETED] Process finished.")
 
 
if __name__ == "__main__":

    app = WindowsXPExplorer()

    app.mainloop()
 