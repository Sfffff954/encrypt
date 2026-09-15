#!/usr/bin/env python3
"""
Datei-Verschlüsselungs-Tool mit GUI
------------------------------------
Verschlüsselt und entschlüsselt einzelne Dateien oder ganze Ordner
(z.B. auf einer externen HDD oder einem USB-Stick) mit einem
passwortbasierten AES-256-Schlüssel (Fernet, aus der Bibliothek
"cryptography"). Das Passwort wird über PBKDF2-HMAC-SHA256 mit
Salt in einen Schlüssel umgewandelt, sodass ein Brute-Force-
Angriff erschwert wird.

Start:  python3 krypto_tool.py
"""

import os
import sys
import base64
import platform
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    import psutil
except ImportError:
    psutil = None

EXT = ".enc"           # Endung für verschlüsselte Dateien
SALT_SIZE = 16
KDF_ITERATIONS = 390_000


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_file(path: str, password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(path, "rb") as f:
        data = f.read()

    token = fernet.encrypt(data)
    out_path = path + EXT

    with open(out_path, "wb") as f:
        f.write(salt + token)

    return out_path


def decrypt_file(path: str, password: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()

    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        data = fernet.decrypt(token)
    except InvalidToken:
        raise ValueError("Falsches Passwort oder beschädigte Datei.")

    if path.endswith(EXT):
        out_path = path[: -len(EXT)]
    else:
        out_path = path + ".dec"

    with open(out_path, "wb") as f:
        f.write(data)

    return out_path


def human_size(num_bytes):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def list_removable_drives():
    """Liefert eine Liste erkannter USB-Sticks / externer Laufwerke als Dicts:
    {"label": Anzeigename, "path": Mount-Pfad, "free": freier Speicher (str)}"""
    drives = []
    system = platform.system()

    if psutil is None:
        return drives

    for part in psutil.disk_partitions(all=False):
        opts = part.opts.split(",") if part.opts else []
        is_removable = False

        if system == "Windows":
            # 'removable' wird von psutil/pywin32 nicht direkt geliefert,
            # daher grobe Heuristik: Laufwerke ungleich C: gelten hier als
            # potentiell extern/wechselbar (USB-Stick, externe HDD).
            is_removable = part.mountpoint.upper() != "C:\\"
        elif system == "Darwin":  # macOS
            is_removable = part.mountpoint.startswith("/Volumes/")
        else:  # Linux
            is_removable = (
                part.mountpoint.startswith("/media/")
                or part.mountpoint.startswith("/mnt/")
                or part.mountpoint.startswith("/run/media/")
            )

        if not is_removable:
            continue

        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue

        label = os.path.basename(part.mountpoint.rstrip("/\\")) or part.mountpoint
        drives.append({
            "label": label,
            "path": part.mountpoint,
            "free": human_size(usage.free),
            "total": human_size(usage.total),
        })

    return drives


def collect_files(paths):
    """Erweitert ausgewählte Ordner rekursiv zu einer Liste von Dateien."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in names:
                    files.append(os.path.join(root, n))
        else:
            files.append(p)
    return files


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Datei-Verschlüsselung – HDD & USB Schutz")
        self.geometry("640x480")
        self.minsize(560, 420)
        self.configure(bg="#1e1e2e")

        self.selected_paths = []
        self.delete_original = tk.BooleanVar(value=False)

        self._build_style()
        self._build_ui()

    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        bg = "#1e1e2e"
        fg = "#e0e0f0"
        accent = "#7aa2f7"
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 15, "bold"), foreground=accent)
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("Accent.TButton", background=accent, foreground="#101018")
        style.configure("TCheckbutton", background=bg, foreground=fg)
        style.configure("TEntry", padding=4)

    def _build_ui(self):
        pad = {"padx": 16, "pady": 8}

        header = ttk.Frame(self)
        header.pack(fill="x", **pad)
        ttk.Label(header, text="🔒 Datei- & USB-/HDD-Verschlüsselung", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Wähle Dateien oder einen ganzen Ordner (z.B. dein USB-Laufwerk) aus,\n"
                 "vergib ein Passwort und verschlüssle oder entschlüssle deine Daten.",
        ).pack(anchor="w", pady=(4, 0))

        # Auswahlbereich
        sel_frame = ttk.Frame(self)
        sel_frame.pack(fill="x", **pad)

        btns = ttk.Frame(sel_frame)
        btns.pack(fill="x")
        ttk.Button(btns, text="📄 Dateien wählen…", command=self.choose_files).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="📁 Ordner wählen…", command=self.choose_folder).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="🔌 USB/HDD erkennen", command=self.detect_drives).pack(side="left")
        ttk.Button(btns, text="✖ Auswahl leeren", command=self.clear_selection).pack(side="right")

        list_frame = ttk.Frame(self)
        list_frame.pack(fill="both", expand=True, padx=16)
        self.listbox = tk.Listbox(
            list_frame, bg="#292a3a", fg="#e0e0f0", selectbackground="#7aa2f7",
            highlightthickness=0, borderwidth=0, font=("Consolas", 9),
        )
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=scrollbar.set)
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Passwort
        pw_frame = ttk.Frame(self)
        pw_frame.pack(fill="x", **pad)
        ttk.Label(pw_frame, text="Passwort:").grid(row=0, column=0, sticky="w")
        self.password_entry = ttk.Entry(pw_frame, show="•", width=30)
        self.password_entry.grid(row=0, column=1, padx=8, sticky="w")

        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            pw_frame, text="anzeigen", variable=self.show_pw, command=self._toggle_pw
        ).grid(row=0, column=2, padx=4)

        ttk.Checkbutton(
            pw_frame, text="Originaldatei nach Vorgang löschen",
            variable=self.delete_original,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))

        # Aktionen
        action_frame = ttk.Frame(self)
        action_frame.pack(fill="x", **pad)
        ttk.Button(
            action_frame, text="🔐 Verschlüsseln", style="Accent.TButton", command=self.run_encrypt
        ).pack(side="left", expand=True, fill="x", padx=(0, 6))
        ttk.Button(
            action_frame, text="🔓 Entschlüsseln", command=self.run_decrypt
        ).pack(side="left", expand=True, fill="x", padx=(6, 0))

        # Statusleiste
        self.status = tk.StringVar(value="Bereit.")
        status_bar = ttk.Label(self, textvariable=self.status, anchor="w")
        status_bar.pack(fill="x", padx=16, pady=(0, 10))

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=16, pady=(0, 12))

    def _toggle_pw(self):
        self.password_entry.configure(show="" if self.show_pw.get() else "•")

    def choose_files(self):
        paths = filedialog.askopenfilenames(title="Dateien auswählen")
        if paths:
            self.selected_paths.extend(paths)
            self._refresh_list()

    def choose_folder(self):
        path = filedialog.askdirectory(title="Ordner / Laufwerk auswählen")
        if path:
            self.selected_paths.append(path)
            self._refresh_list()

    def detect_drives(self):
        if psutil is None:
            messagebox.showerror(
                "Fehlt",
                "Das Modul 'psutil' ist nicht installiert.\n\n"
                "Bitte installieren mit:\npip install psutil",
            )
            return

        drives = list_removable_drives()
        if not drives:
            messagebox.showinfo(
                "Keine Laufwerke gefunden",
                "Es wurden keine externen Laufwerke (USB-Stick/HDD) erkannt.\n\n"
                "Stelle sicher, dass das Laufwerk angeschlossen und eingebunden (gemountet) ist,\n"
                "oder wähle den Ordner manuell über '📁 Ordner wählen…' aus.",
            )
            return

        self._show_drive_picker(drives)

    def _show_drive_picker(self, drives):
        win = tk.Toplevel(self)
        win.title("Erkannte Laufwerke")
        win.geometry("460x260")
        win.configure(bg="#1e1e2e")
        win.transient(self)
        win.grab_set()

        ttk.Label(win, text="Gefundene USB-Sticks / externe Laufwerke:", style="TLabel").pack(
            anchor="w", padx=14, pady=(14, 6)
        )

        list_frame = ttk.Frame(win)
        list_frame.pack(fill="both", expand=True, padx=14)
        drive_list = tk.Listbox(
            list_frame, bg="#292a3a", fg="#e0e0f0", selectbackground="#7aa2f7",
            selectmode="multiple", highlightthickness=0, borderwidth=0, font=("Consolas", 9),
        )
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=drive_list.yview)
        drive_list.configure(yscrollcommand=scrollbar.set)
        drive_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        for d in drives:
            drive_list.insert(
                tk.END, f"{d['label']}   ({d['path']})   frei: {d['free']} / {d['total']}"
            )

        def add_selected():
            for i in drive_list.curselection():
                self.selected_paths.append(drives[i]["path"])
            self._refresh_list()
            win.destroy()

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=14, pady=12)
        ttk.Button(btn_frame, text="Abbrechen", command=win.destroy).pack(side="right", padx=(6, 0))
        ttk.Button(
            btn_frame, text="Ausgewählte hinzufügen", style="Accent.TButton", command=add_selected
        ).pack(side="right")

    def clear_selection(self):
        self.selected_paths = []
        self._refresh_list()

    def _refresh_list(self):
        self.listbox.delete(0, tk.END)
        for p in self.selected_paths:
            self.listbox.insert(tk.END, p)

    def _validate(self):
        if not self.selected_paths:
            messagebox.showwarning("Hinweis", "Bitte zuerst Dateien oder einen Ordner auswählen.")
            return False
        if not self.password_entry.get():
            messagebox.showwarning("Hinweis", "Bitte ein Passwort eingeben.")
            return False
        return True

    def run_encrypt(self):
        if not self._validate():
            return
        self._run_job(mode="encrypt")

    def run_decrypt(self):
        if not self._validate():
            return
        self._run_job(mode="decrypt")

    def _run_job(self, mode):
        password = self.password_entry.get()
        files = collect_files(self.selected_paths)
        if not files:
            messagebox.showinfo("Hinweis", "Keine Dateien gefunden.")
            return

        self.progress.configure(maximum=len(files), value=0)
        thread = threading.Thread(target=self._worker, args=(files, password, mode), daemon=True)
        thread.start()

    def _worker(self, files, password, mode):
        ok, failed = 0, []
        for i, path in enumerate(files, start=1):
            try:
                if mode == "encrypt":
                    if path.endswith(EXT):
                        continue  # bereits verschlüsselt
                    out = encrypt_file(path, password)
                else:
                    if not path.endswith(EXT):
                        continue  # keine .enc-Datei
                    out = decrypt_file(path, password)

                if self.delete_original.get():
                    os.remove(path)

                ok += 1
                self._set_status(f"Verarbeitet ({i}/{len(files)}): {os.path.basename(out)}")
            except Exception as e:
                failed.append(f"{os.path.basename(path)}: {e}")

            self.progress.after(0, lambda v=i: self.progress.configure(value=v))

        summary = f"{ok} Datei(en) erfolgreich {'verschlüsselt' if mode == 'encrypt' else 'entschlüsselt'}."
        if failed:
            summary += f"\n\n{len(failed)} Fehler:\n" + "\n".join(failed[:10])
            self.after(0, lambda: messagebox.showwarning("Ergebnis", summary))
        else:
            self.after(0, lambda: messagebox.showinfo("Ergebnis", summary))
        self._set_status("Fertig.")

    def _set_status(self, text):
        self.status.set(text)


if __name__ == "__main__":
    app = App()
    app.mainloop()
