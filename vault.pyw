import os
import json
import base64
import time
import datetime
import requests
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import pyotp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyperclip
import sys
import traceback
import win32com.client
import win32gui
import win32con
import secrets
import string

# Debug print to check script start
print("Script started at", time.strftime("%H:%M:%S"))

# Test tkinter functionality
print("Testing tkinter initialization")
try:
    test_root = tk.Tk()
    test_root.title("Test Window")
    tk.Label(test_root, text="Testing tkinter").pack()
    test_root.update()
    test_root.withdraw()
    test_root.destroy()
    print("Tkinter test successful")
except Exception as e:
    print(f"Tkinter test failed: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

# ---------- Paths ----------
appdata_dir = os.path.join(os.getenv('APPDATA', ''), 'iimatAccountManager')
print(f"AppData directory: {appdata_dir}")
os.makedirs(appdata_dir, exist_ok=True)
VAULT_FILE = os.path.join(appdata_dir, 'vault.json')
# Handle icon path for bundled executable
if getattr(sys, 'frozen', False):
    ICON_FILE = os.path.join(sys._MEIPASS, 'photo.ico')
else:
    ICON_FILE = os.path.join(appdata_dir, 'photo.ico')
print(f"Vault file: {VAULT_FILE}")
print(f"Icon file: {ICON_FILE}")

# Download and validate icon if missing (only when not bundled)
if not getattr(sys, 'frozen', False) and not os.path.exists(ICON_FILE):
    print("Downloading icon...")
    try:
        url = "https://raw.githubusercontent.com/iiMAtEAs/accmanager/main/photo.ico"
        r = requests.get(url, timeout=5)
        if r.status_code == 200:
            with open(ICON_FILE, 'wb') as f:
                f.write(r.content)
            # Verify icon file
            if os.path.getsize(ICON_FILE) > 0:
                print("Icon downloaded and verified successfully")
            else:
                print("Downloaded icon file is empty")
        else:
            print(f"Failed to download icon, status code: {r.status_code}")
    except requests.RequestException as e:
        print(f"Icon download failed: {str(e)}")

# Validate icon file existence
if not os.path.exists(ICON_FILE):
    print(f"Warning: Icon file {ICON_FILE} does not exist")

# ---------- Create Desktop Shortcut ----------
def create_shortcut():
    print("Creating desktop shortcut")
    try:
        desktop = os.path.join(os.getenv('USERPROFILE'), 'Desktop')
        shortcut_path = os.path.join(desktop, 'Account Manager.lnk')
        if getattr(sys, 'frozen', False):
            target_path = sys.executable
            working_dir = os.path.dirname(sys.executable)
            arguments = ""
        else:
            script_path = os.path.abspath(__file__)
            target_path = sys.executable
            arguments = f'"{script_path}"'
            working_dir = os.path.dirname(script_path)
        
        if not os.path.exists(shortcut_path):
            shell = win32com.client.Dispatch('WScript.Shell')
            shortcut = shell.CreateShortCut(shortcut_path)
            shortcut.Targetpath = target_path
            shortcut.Arguments = arguments
            shortcut.WorkingDirectory = working_dir
            if os.path.exists(ICON_FILE):
                shortcut.IconLocation = ICON_FILE
            shortcut.Description = "Account Manager"
            shortcut.save()
            print("Desktop shortcut created successfully")
        else:
            print("Desktop shortcut already exists")
    except Exception as e:
        print(f"Error creating shortcut: {str(e)}")
        traceback.print_exc()

# ---------- Encryption helpers ----------
def key_from_password(pw: str) -> bytes:
    print("Generating key from password")
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'iimatAccountManagerSalt',
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(pw.encode()))
    except Exception as e:
        print(f"Error in key_from_password: {str(e)}")
        raise

def encrypt_data(data, pw):
    print("Encrypting data")
    try:
        f = Fernet(key_from_password(pw))
        return f.encrypt(json.dumps(data).encode()).decode()
    except Exception as e:
        print(f"Error in encrypt_data: {str(e)}")
        raise

def decrypt_data(enc, pw):
    print("Decrypting data")
    try:
        f = Fernet(key_from_password(pw))
        return json.loads(f.decrypt(enc.encode()).decode())
    except Exception as e:
        print(f"Error in decrypt_data: {str(e)}")
        raise

# ---------- Dark Prompt ----------
def dark_prompt(title, label, show="", parent=None):
    print(f"Showing dark prompt: {title}")
    try:
        prompt = tk.Toplevel(parent)
        prompt.configure(bg="#0b0b0b")
        prompt.title(title)
        prompt.geometry("300x120")
        prompt.resizable(False, False)
        # Ensure icon is set for titlebar and taskbar
        if os.path.exists(ICON_FILE):
            try:
                # Set icon for titlebar
                prompt.iconbitmap(ICON_FILE)
                print(f"Set iconbitmap for prompt: {ICON_FILE}")
                # Set icon for Tkinter's internal photo
                icon = tk.PhotoImage(file=ICON_FILE)
                prompt.iconphoto(True, icon)
                print(f"Set iconphoto for prompt: {ICON_FILE}")
                # Ensure window is updated before setting taskbar icon
                prompt.update()
                # Set taskbar icon using win32gui
                hwnd = prompt.winfo_id()
                hicon = win32gui.LoadImage(0, ICON_FILE, win32con.IMAGE_ICON, 0, 0, win32con.LR_LOADFROMFILE)
                win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_SMALL, hicon)
                win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_BIG, hicon)
                print(f"Set taskbar icon for prompt using win32gui: {ICON_FILE}")
            except Exception as e:
                print(f"Failed to set prompt icon: {str(e)}")
                traceback.print_exc()
        else:
            print(f"Icon file {ICON_FILE} not found for prompt")
        tk.Label(prompt, text=label, bg="#0b0b0b", fg="#e0e0e0", font=("Arial", 10)).pack(pady=5)
        entry = tk.Entry(prompt, show=show, bg="#222222", fg="#e0e0e0", insertbackground="#e0e0e0", font=("Arial", 10))
        entry.pack(pady=5, padx=10, fill="x")
        result = {"value": None}
        def ok():
            print("OK button clicked")
            result['value'] = entry.get()
            prompt.destroy()
        tk.Button(prompt, text="OK", command=ok, bg="#1a1a1a", fg="#ffffff", activebackground="#333333", activeforeground="#ffffff", font=("Arial", 10)).pack(pady=5)
        entry.bind("<Return>", lambda e: ok())
        entry.focus()
        prompt.wait_window()
        print(f"Dark prompt result: [hidden]")
        return result['value']
    except Exception as e:
        print(f"Error in dark_prompt: {str(e)}")
        traceback.print_exc()
        raise

# ---------- Root window (hidden initially) ----------
print("Initializing root window")
try:
    root = tk.Tk()
    root.withdraw()
    if os.path.exists(ICON_FILE):
        try:
            root.iconbitmap(ICON_FILE)
            print(f"Set iconbitmap for root window: {ICON_FILE}")
            icon = tk.PhotoImage(file=ICON_FILE)
            root.iconphoto(True, icon)
            print(f"Set iconphoto for root window: {ICON_FILE}")
            # Ensure window is updated before setting taskbar icon
            root.update()
            hwnd = root.winfo_id()
            hicon = win32gui.LoadImage(0, ICON_FILE, win32con.IMAGE_ICON, 0, 0, win32con.LR_LOADFROMFILE)
            win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_SMALL, hicon)
            win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_BIG, hicon)
            print(f"Set taskbar icon for root window: {ICON_FILE}")
        except Exception as e:
            print(f"Failed to set root window icon: {str(e)}")
            traceback.print_exc()
    else:
        print(f"Icon file {ICON_FILE} not found for root window")
    print("Root window initialized and hidden")
except Exception as e:
    print(f"Error initializing root window: {str(e)}")
    traceback.print_exc()
    sys.exit(1)

# ---------- Master password ----------
print("Prompting for master password")
try:
    pw = dark_prompt("Master Password", "Enter master password:", show="*", parent=root)
    if not pw:
        print("No password entered, exiting")
        root.destroy()
        sys.exit(0)
except Exception as e:
    print(f"Error during password prompt: {str(e)}")
    traceback.print_exc()
    root.destroy()
    sys.exit(1)

# ---------- Load vault ----------
vault = {}
print(f"Loading vault from {VAULT_FILE}")
try:
    if os.path.exists(VAULT_FILE):
        try:
            vault_data = json.load(open(VAULT_FILE))
            vault = decrypt_data(vault_data["data"], pw)
            print("Vault loaded successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Incorrect password or corrupted vault: {str(e)}", parent=root)
            print(f"Vault load failed: {str(e)}")
            root.destroy()
            sys.exit(1)
    else:
        vault = {"tabs": {"Main": {"folders": {"Default": {"accounts": [], "totp": []}}}}}
        with open(VAULT_FILE, 'w') as f:
            json.dump({"data": encrypt_data(vault, pw)}, f)
        print("New vault created")
except Exception as e:
    messagebox.showerror("Error", f"Failed to initialize vault: {str(e)}", parent=root)
    print(f"Vault initialization failed: {str(e)}")
    root.destroy()
    sys.exit(1)

# Create desktop shortcut after vault is loaded
create_shortcut()

# ---------- Show main window ----------
print("Showing main window")
try:
    root.deiconify()
    root.title("Account Manager")
    # Set initial window size to accommodate side-by-side tables
    root.geometry("1000x600")
    root.configure(bg="#0b0b0b")
    # Make window resizable
    root.resizable(True, True)
    if os.path.exists(ICON_FILE):
        try:
            root.iconbitmap(ICON_FILE)
            print(f"Set iconbitmap for main window: {ICON_FILE}")
            icon = tk.PhotoImage(file=ICON_FILE)
            root.iconphoto(True, icon)
            print(f"Set iconphoto for main window: {ICON_FILE}")
            # Ensure window is updated before setting taskbar icon
            root.update()
            hwnd = root.winfo_id()
            hicon = win32gui.LoadImage(0, ICON_FILE, win32con.IMAGE_ICON, 0, 0, win32con.LR_LOADFROMFILE)
            win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_SMALL, hicon)
            win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_BIG, hicon)
            print(f"Set taskbar icon for main window: {ICON_FILE}")
        except Exception as e:
            print(f"Failed to set main window icon: {str(e)}")
            traceback.print_exc()
    else:
        print(f"Icon file {ICON_FILE} not found for main window")
except Exception as e:
    print(f"Error showing main window: {str(e)}")
    traceback.print_exc()
    root.destroy()
    sys.exit(1)

# ---------- Apply Dark Theme ----------
print("Applying dark theme")
try:
    style = ttk.Style()
    style.theme_use("default")
    style.configure("TNotebook", background="#0b0b0b", borderwidth=0)
    style.configure("TNotebook.Tab", background="#1a1a1a", foreground="#ffffff", padding=[10, 5])
    style.map("TNotebook.Tab", background=[("selected", "#333333")], foreground=[("selected", "#ffffff")])
    style.configure("Treeview", background="#141414", foreground="#e0e0e0", fieldbackground="#141414", font=("Arial", 10))
    style.configure("Treeview.Heading", background="#1a1a1a", foreground="#ffffff", font=("Arial", 10))
    style.map("Treeview", background=[("selected", "#333333")], foreground=[("selected", "#ffffff")])
    style.configure("TButton", background="#1a1a1a", foreground="#ffffff", font=("Arial", 10))
    style.map("TButton", background=[("active", "#333333")], foreground=[("active", "#ffffff")])
    style.configure("TLabel", background="#0b0b0b", foreground="#e0e0e0", font=("Arial", 10))
    style.configure("TFrame", background="#0b0b0b")
    style.configure("TEntry", fieldbackground="#222222", foreground="#e0e0e0", insertbackground="#e0e0e0", font=("Arial", 10))
    style.map("TEntry", fieldbackground=[("active", "#222222")], foreground=[("active", "#e0e0e0")])
    style.configure("Vertical.TScrollbar", background="#1a1a1a", troughcolor="#0b0b0b", arrowcolor="#e0e0e0", width=10)
    style.map("Vertical.TScrollbar", background=[("active", "#333333")])
    root.option_add("*Menu.Background", "#0b0b0b")
    root.option_add("*Menu.Foreground", "#e0e0e0")
    root.option_add("*Menu.activeBackground", "#333333")
    root.option_add("*Menu.activeForeground", "#ffffff")
    print("Dark theme applied successfully")
except Exception as e:
    print(f"Error applying dark theme: {str(e)}")
    traceback.print_exc()

# ---------- Notebook ----------
print("Setting up notebook")
try:
    tab_control = ttk.Notebook(root)
    tab_control.pack(expand=1, fill="both", pady=(0, 5))
except Exception as e:
    print(f"Error setting up notebook: {str(e)}")
    traceback.print_exc()
    root.destroy()
    sys.exit(1)

# ---------- Vault structures ----------
tab_frames = {}
folder_notebooks = {}
folder_frames = {}
folder_trees = {}
folder_labels = {}  # To store account and TOTP count labels
search_entries = {}  # To store search entry widgets

# ---------- Save Vault ----------
def save_vault():
    print("Saving vault")
    try:
        with open(VAULT_FILE, 'w') as f:
            json.dump({"data": encrypt_data(vault, pw)}, f)
        print("Vault saved successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save vault: {str(e)}", parent=root)
        print(f"Error saving vault: {str(e)}")
        traceback.print_exc()

# ---------- Helper Functions ----------
def update_tab_label(tab_name):
    print(f"Updating tab label for {tab_name}")
    try:
        total_accounts = 0
        total_totp = 0
        for folder_name in vault["tabs"][tab_name]["folders"]:
            total_accounts += len(vault["tabs"][tab_name]["folders"][folder_name].get("accounts", []))
            total_totp += len(vault["tabs"][tab_name]["folders"][folder_name].get("totp", []))
        tab_control.tab(tab_frames[tab_name], text=f"{tab_name} ({total_accounts} accounts, {total_totp} 2FA)")
        print(f"Tab {tab_name} updated: {total_accounts} accounts, {total_totp} 2FA")
    except Exception as e:
        print(f"Error updating tab label: {str(e)}")
        traceback.print_exc()

def update_account_table(tab_name, folder_name, search_query=""):
    print(f"Updating account table for {tab_name}/{folder_name} with search_query: {search_query}")
    try:
        vault_tree, _ = folder_trees[(tab_name, folder_name)]
        vault_tree.delete(*vault_tree.get_children())
        accounts = vault["tabs"][tab_name]["folders"][folder_name].get("accounts", [])
        filtered_accounts = [
            a for a in accounts
            if search_query.lower() in a["user"].lower() or search_query.lower() in a["pass"].lower()
        ]
        for a in filtered_accounts:
            vault_tree.insert("", "end", values=(a["user"], a["pass"], a.get("added_at", "N/A")))
        # Update account count label
        account_label = folder_labels[(tab_name, folder_name)]["accounts"]
        account_label.config(text=f"Accounts: {len(filtered_accounts)}")
        update_tab_label(tab_name)
        save_vault()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update account table: {str(e)}", parent=root)
        print(f"Error updating account table: {str(e)}")
        traceback.print_exc()

def update_totp_table(tab_name, folder_name, search_query=""):
    print(f"Updating TOTP table for {tab_name}/{folder_name} with search_query: {search_query}")
    try:
        _, totp_tree = folder_trees[(tab_name, folder_name)]
        totp_tree.delete(*totp_tree.get_children())
        totp_list = vault["tabs"][tab_name]["folders"][folder_name].get("totp", [])
        filtered_totp = [
            t for t in totp_list
            if search_query.lower() in t["name"].lower() or search_query.lower() in pyotp.TOTP(t["secret"]).now().lower()
        ]
        for t in filtered_totp:
            totp_tree.insert("", "end", values=(t["name"], pyotp.TOTP(t["secret"]).now(), t.get("added_at", "N/A")))
        # Update TOTP count label
        totp_label = folder_labels[(tab_name, folder_name)]["totp"]
        totp_label.config(text=f"2FA Entries: {len(filtered_totp)}")
        update_tab_label(tab_name)
        save_vault()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to update TOTP table: {str(e)}", parent=root)
        print(f"Error updating TOTP table: {str(e)}")
        traceback.print_exc()

def refresh_totp_codes():
    print("Refreshing TOTP codes")
    try:
        for (tab_name, folder_name) in folder_trees.keys():
            search_entry = search_entries.get((tab_name, folder_name))
            search_query = search_entry.get() if search_entry else ""
            update_totp_table(tab_name, folder_name, search_query)
        root.after(30000, refresh_totp_codes)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to refresh TOTP codes: {str(e)}", parent=root)
        print(f"Error refreshing TOTP codes: {str(e)}")
        traceback.print_exc()

# ---------- Search Function ----------
def search_in_folder(tab_name, folder_name, event=None):
    print(f"Searching in {tab_name}/{folder_name}")
    try:
        search_entry = search_entries.get((tab_name, folder_name))
        if not search_entry:
            print(f"No search entry found for {tab_name}/{folder_name}")
            return
        search_query = search_entry.get()
        update_account_table(tab_name, folder_name, search_query)
        update_totp_table(tab_name, folder_name, search_query)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to search: {str(e)}", parent=root)
        print(f"Error searching: {str(e)}")
        traceback.print_exc()

# Bind Ctrl+F to focus the search box
def bind_ctrl_f(tab_name, folder_name):
    print(f"Binding Ctrl+F for {tab_name}/{folder_name}")
    try:
        search_entry = search_entries.get((tab_name, folder_name))
        if not search_entry:
            raise ValueError(f"Search entry for {tab_name}/{folder_name} not found")
        def focus_search(event):
            print(f"Ctrl+F focusing search box for {tab_name}/{folder_name}")
            search_entry.focus_set()
        root.bind("<Control-f>", focus_search, add="+")
    except Exception as e:
        print(f"Error binding Ctrl+F: {str(e)}")
        traceback.print_exc()

# ---------- Folder Functions ----------
def add_folder(tab_name):
    print(f"Adding folder to tab {tab_name}")
    try:
        folder_name = dark_prompt("Folder Name", "Enter folder name:", show="", parent=root)
        if not folder_name:
            print("No folder name entered")
            return
        if folder_name in vault["tabs"][tab_name]["folders"]:
            messagebox.showerror("Error", "Folder already exists", parent=root)
            print(f"Folder {folder_name} already exists")
            return
        vault["tabs"][tab_name]["folders"][folder_name] = {"accounts": [], "totp": []}
        create_folder_frame(tab_name, folder_name)
        update_tab_label(tab_name)
        save_vault()
        print("Folder added successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add folder: {str(e)}", parent=root)
        print(f"Error adding folder: {str(e)}")
        traceback.print_exc()

def delete_folder(tab_name, folder_name):
    print(f"Deleting folder {folder_name} from tab {tab_name}")
    try:
        if messagebox.askyesno("Delete Folder", f"Delete folder '{folder_name}'?", parent=root):
            notebook = folder_notebooks.get(tab_name)
            folder_frame = folder_frames.get((tab_name, folder_name))
            if not notebook or not folder_frame:
                raise ValueError(f"Notebook or folder frame for {tab_name}/{folder_name} not found")
            folder_id = notebook.index(folder_frames[(tab_name, folder_name)])
            notebook.forget(folder_id)
            vault["tabs"][tab_name]["folders"].pop(folder_name, None)
            folder_trees.pop((tab_name, folder_name), None)
            folder_frames.pop((tab_name, folder_name), None)
            folder_labels.pop((tab_name, folder_name), None)
            search_entries.pop((tab_name, folder_name), None)
            update_tab_label(tab_name)
            save_vault()
            print("Folder deleted successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete folder: {str(e)}", parent=root)
        print(f"Error deleting folder: {str(e)}")
        traceback.print_exc()

def copy_folder(tab_name, folder_name):
    print(f"Copying folder {folder_name} from tab {tab_name}")
    try:
        folder = vault["tabs"][tab_name]["folders"][folder_name]
        text = ""
        text += f"Folder: {folder_name}\n"
        text += "Accounts:\n" + "\n".join([f"{a['user']}:{a['pass']} ({a.get('added_at', 'N/A')})" for a in folder.get("accounts", [])]) + "\n"
        text += "TOTP:\n" + "\n".join([f"{t['name']}:{t['secret']}" for t in folder.get("totp", [])]) + "\n"
        pyperclip.copy(text)
        messagebox.showinfo("Copied", f"Copied all contents of folder '{folder_name}'", parent=root)
        print("Folder copied successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to copy folder: {str(e)}", parent=root)
        print(f"Error copying folder: {str(e)}")
        traceback.print_exc()

def create_folder_frame(tab_name, folder_name):
    print(f"Creating folder frame for {tab_name}/{folder_name}")
    try:
        notebook = folder_notebooks.get(tab_name)
        if not notebook:
            raise ValueError(f"Notebook for tab {tab_name} not found")
        folder_frame = ttk.Frame(notebook)
        notebook.add(folder_frame, text=folder_name)
        folder_frames[(tab_name, folder_name)] = folder_frame

        # Search bar
        search_frame = ttk.Frame(folder_frame)
        search_frame.pack(fill="x", pady=5)
        ttk.Label(search_frame, text="Search:").pack(side="left", padx=(5, 2))
        search_entry = ttk.Entry(search_frame, style="TEntry")
        search_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        search_entries[(tab_name, folder_name)] = search_entry
        search_entry.bind("<KeyRelease>", lambda event: search_in_folder(tab_name, folder_name, event))

        # Container for side-by-side layout
        tables_frame = ttk.Frame(folder_frame)
        tables_frame.pack(expand=True, fill="both")

        # Configure grid to make both columns equal width
        tables_frame.grid_columnconfigure(0, weight=1)
        tables_frame.grid_columnconfigure(1, weight=1)
        tables_frame.grid_rowconfigure(0, weight=1)

        # Account table (left) with scrollbar
        account_frame = ttk.Frame(tables_frame)
        account_frame.grid(row=0, column=0, sticky="nsew", padx=(5, 2))
        account_frame.grid_columnconfigure(0, weight=1)
        account_frame.grid_rowconfigure(0, weight=1)
        vault_tree = ttk.Treeview(account_frame, columns=("User", "Password", "Added At"), show="headings", height=15, selectmode="extended")
        vault_tree.heading("User", text="User")
        vault_tree.heading("Password", text="Password")
        vault_tree.heading("Added At", text="Added At")
        vault_tree.column("User", width=200, stretch=True)
        vault_tree.column("Password", width=200, stretch=True)
        vault_tree.column("Added At", width=150, stretch=True)
        vault_scroll = ttk.Scrollbar(account_frame, orient="vertical", command=vault_tree.yview)
        vault_scroll.grid(row=0, column=1, sticky="ns")
        vault_tree.configure(yscrollcommand=vault_scroll.set)
        vault_tree.grid(row=0, column=0, sticky="nsew")
        # Account count label
        account_label = ttk.Label(account_frame, text="Accounts: 0")
        account_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=2)

        # 2FA table (right) with scrollbar
        totp_frame = ttk.Frame(tables_frame)
        totp_frame.grid(row=0, column=1, sticky="nsew", padx=(2, 5))
        totp_frame.grid_columnconfigure(0, weight=1)
        totp_frame.grid_rowconfigure(0, weight=1)
        totp_tree = ttk.Treeview(totp_frame, columns=("Username", "Code", "Added At"), show="headings", height=15, selectmode="extended")
        totp_tree.heading("Username", text="Username")
        totp_tree.heading("Code", text="Code")
        totp_tree.heading("Added At", text="Added At")
        totp_tree.column("Username", width=200, stretch=True)
        totp_tree.column("Code", width=200, stretch=True)
        totp_tree.column("Added At", width=150, stretch=True)
        totp_scroll = ttk.Scrollbar(totp_frame, orient="vertical", command=totp_tree.yview)
        totp_scroll.grid(row=0, column=1, sticky="ns")
        totp_tree.configure(yscrollcommand=totp_scroll.set)
        totp_tree.grid(row=0, column=0, sticky="nsew")
        # TOTP count label
        totp_label = ttk.Label(totp_frame, text="2FA Entries: 0")
        totp_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=2)

        # Store labels
        folder_labels[(tab_name, folder_name)] = {"accounts": account_label, "totp": totp_label}

        # Function to resize Treeview columns
        def resize_columns(event=None):
            try:
                # Get the current width of the account_frame (same as totp_frame due to equal weights)
                frame_width = account_frame.winfo_width()
                if frame_width <= 0:  # Avoid division by zero during initialization
                    return
                # Subtract scrollbar width (approx 10 pixels) and some padding
                available_width = max(50, frame_width - 20)
                # Distribute width equally: ~33.33% for each column
                col_width = int(available_width / 3)
                # Update account table columns
                vault_tree.column("User", width=col_width, stretch=True)
                vault_tree.column("Password", width=col_width, stretch=True)
                vault_tree.column("Added At", width=col_width, stretch=True)
                # Update TOTP table columns
                totp_tree.column("Username", width=col_width, stretch=True)
                totp_tree.column("Code", width=col_width, stretch=True)
                totp_tree.column("Added At", width=col_width, stretch=True)
                print(f"Resized columns for {tab_name}/{folder_name}: User={col_width}, Pass/Code={col_width}, Date={col_width}")
            except Exception as e:
                print(f"Error resizing columns: {str(e)}")
                traceback.print_exc()

        # Bind resize event to tables_frame
        tables_frame.bind("<Configure>", resize_columns)

        # Buttons
        btn_frame = ttk.Frame(folder_frame)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Add Account", command=lambda: add_account(tab_name, folder_name)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Add 2FA", command=lambda: add_2fa(tab_name, folder_name)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Import Accounts", command=lambda: import_accounts(tab_name, folder_name)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Import 2FA", command=lambda: import_2fa(tab_name, folder_name)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Export 2FA", command=lambda: export_totp(tab_name, folder_name)).pack(side="left", padx=5)

        folder_trees[(tab_name, folder_name)] = (vault_tree, totp_tree)
        update_account_table(tab_name, folder_name)
        update_totp_table(tab_name, folder_name)

        # Bind Ctrl+F
        bind_ctrl_f(tab_name, folder_name)

        # Right-click Folder
        def folder_right_click(event):
            try:
                x, y = event.x, event.y
                elem = notebook.identify(x, y)
                if "label" in elem:
                    idx = notebook.index("@%d,%d" % (x, y))
                    folder_name = notebook.tab(idx, "text")
                    menu = tk.Menu(root, tearoff=0, bg="#0b0b0b", fg="#e0e0e0", activebackground="#333333", activeforeground="#ffffff")
                    menu.add_command(label="Copy All", command=lambda: copy_folder(tab_name, folder_name))
                    menu.add_command(label="Delete Folder", command=lambda: delete_folder(tab_name, folder_name))
                    menu.tk_popup(event.x_root, event.y_root)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to handle folder right-click: {str(e)}", parent=root)
                print(f"Error in folder_right_click for {tab_name}: {str(e)}")
                traceback.print_exc()
        notebook.bind("<Button-3>", folder_right_click)

        # Right-click Vault entry
        def vault_right_click(event):
            try:
                iid = vault_tree.identify_row(event.y)
                if iid:
                    # Do not clear existing selections
                    selected_iids = vault_tree.selection()
                    if iid not in selected_iids:
                        vault_tree.selection_add(iid)
                    menu = tk.Menu(root, tearoff=0, bg="#0b0b0b", fg="#e0e0e0", activebackground="#333333", activeforeground="#ffffff")
                    def copy_selected_accounts():
                        selected = []
                        for sid in selected_iids:
                            user, pwd, _ = vault_tree.item(sid)["values"]
                            selected.append(f"{user}:{pwd}")
                        pyperclip.copy("\n".join(selected))
                        messagebox.showinfo("Copied", "Selected accounts copied to clipboard", parent=root)
                    menu.add_command(label="Copy selected user:pass", command=copy_selected_accounts)
                    menu.add_separator()
                    menu.add_command(label="Delete selected entries", command=lambda: delete_account(tab_name, folder_name, selected_iids))
                    menu.tk_popup(event.x_root, event.y_root)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to handle vault right-click: {str(e)}", parent=root)
                print(f"Error in vault_right_click: {str(e)}")
                traceback.print_exc()
        vault_tree.bind("<Button-3>", vault_right_click)

        # Right-click TOTP entry
        def totp_right_click(event):
            try:
                iid = totp_tree.identify_row(event.y)
                if iid:
                    # Do not clear existing selections
                    selected_iids = totp_tree.selection()
                    if iid not in selected_iids:
                        totp_tree.selection_add(iid)
                    menu = tk.Menu(root, tearoff=0, bg="#0b0b0b", fg="#e0e0e0", activebackground="#333333", activeforeground="#ffffff")
                    def copy_selected_totp():
                        selected = []
                        for sid in selected_iids:
                            name, code, _ = totp_tree.item(sid)["values"]
                            selected.append(f"{name}:{code}")
                        pyperclip.copy("\n".join(selected))
                        messagebox.showinfo("Copied", "Selected 2FA entries copied to clipboard", parent=root)
                    menu.add_command(label="Copy selected username:code", command=copy_selected_totp)
                    menu.add_separator()
                    menu.add_command(label="Delete selected entries", command=lambda: delete_totp(tab_name, folder_name, selected_iids))
                    menu.tk_popup(event.x_root, event.y_root)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to handle TOTP right-click: {str(e)}", parent=root)
                print(f"Error in totp_right_click: {str(e)}")
                traceback.print_exc()
        totp_tree.bind("<Button-3>", totp_right_click)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create folder frame: {str(e)}", parent=root)
        print(f"Error creating folder frame: {str(e)}")
        traceback.print_exc()

# ---------- Tab Functions ----------
def add_tab():
    print("Adding new tab")
    try:
        tab_name = dark_prompt("Tab Name", "Enter tab name:", show="", parent=root)
        if not tab_name:
            print("No tab name entered")
            return
        if tab_name in vault["tabs"]:
            messagebox.showerror("Error", "Tab already exists", parent=root)
            print(f"Tab {tab_name} already exists")
            return
        tab_frame = ttk.Frame(tab_control)
        tab_control.add(tab_frame, text=f"{tab_name} (0 accounts, 0 2FA)")
        tab_frames[tab_name] = tab_frame
        vault["tabs"][tab_name] = {"folders": {"Default": {"accounts": [], "totp": []}}}
        notebook = ttk.Notebook(tab_frame)
        notebook.pack(expand=True, fill="both")
        folder_notebooks[tab_name] = notebook
        create_folder_frame(tab_name, "Default")
        save_vault()
        print("Tab added successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add tab: {str(e)}", parent=root)
        print(f"Error adding tab: {str(e)}")
        traceback.print_exc()

def tab_right_click(event):
    print("Handling tab right-click")
    try:
        x, y = event.x, event.y
        elem = tab_control.identify(x, y)
        if "label" in elem:
            idx = tab_control.index("@%d,%d" % (x, y))
            tab_name = tab_control.tab(idx, "text").split(" (")[0]
            menu = tk.Menu(root, tearoff=0, bg="#0b0b0b", fg="#e0e0e0", activebackground="#333333", activeforeground="#ffffff")
            menu.add_command(label="Copy All", command=lambda: copy_tab(tab_name))
            menu.add_command(label="Delete Tab", command=lambda: delete_tab(tab_name))
            menu.tk_popup(event.x_root, event.y_root)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to handle tab right-click: {str(e)}", parent=root)
        print(f"Error in tab_right_click: {str(e)}")
        traceback.print_exc()

def copy_tab(tab_name):
    print(f"Copying tab {tab_name}")
    try:
        text = ""
        for folder_name in vault["tabs"][tab_name]["folders"]:
            folder = vault["tabs"][tab_name]["folders"][folder_name]
            text += f"Folder: {folder_name}\n"
            text += "Accounts:\n" + "\n".join([f"{a['user']}:{a['pass']} ({a.get('added_at', 'N/A')})" for a in folder.get("accounts", [])]) + "\n"
            text += "TOTP:\n" + "\n".join([f"{t['name']}:{t['secret']}" for t in folder.get("totp", [])]) + "\n\n"
        pyperclip.copy(text)
        messagebox.showinfo("Copied", f"Copied all contents of tab '{tab_name}'", parent=root)
        print("Tab copied successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to copy tab: {str(e)}", parent=root)
        print(f"Error copying tab: {str(e)}")
        traceback.print_exc()

def delete_tab(tab_name):
    print(f"Deleting tab {tab_name}")
    try:
        if messagebox.askyesno("Delete Tab", f"Delete tab '{tab_name}'?", parent=root):
            for folder_name in list(vault["tabs"][tab_name]["folders"].keys()):
                folder_trees.pop((tab_name, folder_name), None)
                folder_frames.pop((tab_name, folder_name), None)
                folder_labels.pop((tab_name, folder_name), None)
                search_entries.pop((tab_name, folder_name), None)
            vault["tabs"].pop(tab_name, None)
            tab_id = tab_control.index(tab_frames[tab_name])
            tab_control.forget(tab_id)
            tab_frames.pop(tab_name)
            folder_notebooks.pop(tab_name, None)
            save_vault()
            print("Tab deleted successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete tab: {str(e)}", parent=root)
        print(f"Error deleting tab: {str(e)}")
        traceback.print_exc()

tab_control.bind("<Button-3>", tab_right_click)

# ---------- Account / 2FA ----------
def add_account(tab_name, folder_name):
    print(f"Adding account to {tab_name}/{folder_name}")
    try:
        folder_frame = folder_frames.get((tab_name, folder_name))
        if not folder_frame:
            raise ValueError(f"Folder frame {tab_name}/{folder_name} not found")
        user = dark_prompt("Username", "Enter username:", show="", parent=folder_frame)
        if not user:
            print("No username entered")
            return
        pwd = dark_prompt("Password", "Enter password:", show="*", parent=folder_frame)
        if not pwd:
            print("No password entered")
            return
        accounts = vault["tabs"][tab_name]["folders"][folder_name]["accounts"]
        for i, acc in enumerate(accounts):
            if acc["user"] == user and acc["pass"] == pwd:
                accounts[i] = {"user": user, "pass": pwd, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                print("Overwriting existing account")
                break
        else:
            accounts.append({"user": user, "pass": pwd, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            print("Appending new account")
        search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
        update_account_table(tab_name, folder_name, search_query)
        print("Account added successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to add account: {str(e)}", parent=root)
        print(f"Error adding account: {str(e)}")
        traceback.print_exc()

def delete_account(tab_name, folder_name, iids):
    print(f"Deleting account(s) from {tab_name}/{folder_name}")
    try:
        vault_tree, _ = folder_trees[(tab_name, folder_name)]
        accounts = vault["tabs"][tab_name]["folders"][folder_name]["accounts"]
        to_remove = []
        for iid in iids:
            user, pwd, _ = vault_tree.item(iid)["values"]
            to_remove.append((user, pwd))
        vault["tabs"][tab_name]["folders"][folder_name]["accounts"] = [
            a for a in accounts
            if (a["user"], a["pass"]) not in to_remove
        ]
        search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
        update_account_table(tab_name, folder_name, search_query)
        print("Account(s) deleted successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete account(s): {str(e)}", parent=root)
        print(f"Error deleting account(s): {str(e)}")
        traceback.print_exc()

def add_2fa(tab_name, folder_name):
    print(f"Adding 2FA to {tab_name}/{folder_name}")
    try:
        folder_frame = folder_frames.get((tab_name, folder_name))
        if not folder_frame:
            raise ValueError(f"Folder frame {tab_name}/{folder_name} not found")
        name = dark_prompt("Username", "Username:", show="", parent=folder_frame)
        if not name:
            print("No username entered")
            return
        secret = dark_prompt("Base32 Secret", "Enter Base32 secret:", show="", parent=folder_frame)
        if not secret:
            print("No secret entered")
            return
        pyotp.TOTP(secret).now()
        totp_list = vault["tabs"][tab_name]["folders"][folder_name]["totp"]
        for i, totp in enumerate(totp_list):
            if totp["name"] == name and totp["secret"] == secret:
                totp_list[i] = {"name": name, "secret": secret, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                print("Overwriting existing 2FA entry")
                break
        else:
            totp_list.append({"name": name, "secret": secret, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            print("Appending new 2FA entry")
        search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
        update_totp_table(tab_name, folder_name, search_query)
        print("2FA added successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid Base32 secret or error adding 2FA: {str(e)}", parent=root)
        print(f"Error adding 2FA: {str(e)}")
        traceback.print_exc()

def delete_totp(tab_name, folder_name, iids):
    print(f"Deleting TOTP from {tab_name}/{folder_name}")
    try:
        _, totp_tree = folder_trees[(tab_name, folder_name)]
        totp_list = vault["tabs"][tab_name]["folders"][folder_name]["totp"]
        to_remove = [totp_tree.item(iid)["values"][0] for iid in iids]
        vault["tabs"][tab_name]["folders"][folder_name]["totp"] = [
            t for t in totp_list if t["name"] not in to_remove
        ]
        search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
        update_totp_table(tab_name, folder_name, search_query)
        print("TOTP deleted successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to delete TOTP: {str(e)}", parent=root)
        print(f"Error deleting TOTP: {str(e)}")
        traceback.print_exc()

# ---------- Import/Export ----------
def import_accounts(tab_name, folder_name):
    print(f"Importing accounts to {tab_name}/{folder_name}")
    try:
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")], parent=root)
        if not file_path:
            print("No file selected for account import")
            return
        accounts = vault["tabs"][tab_name]["folders"][folder_name]["accounts"]
        if file_path.endswith('.txt'):
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if line and ":" in line:
                        user, pwd = line.split(":", 1)
                        if user and pwd:
                            for i, acc in enumerate(accounts):
                                if acc["user"] == user and acc["pass"] == pwd:
                                    accounts[i] = {"user": user, "pass": pwd, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                                    print(f"Overwriting account {user}:{pwd}")
                                    break
                            else:
                                accounts.append({"user": user, "pass": pwd, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                                print(f"Appending account {user}:{pwd}")
        elif file_path.endswith('.json'):
            with open(file_path) as f:
                data = json.load(f)
                imported_accounts = data.get("accounts", [])
                for a in imported_accounts:
                    if "user" in a and "pass" in a:
                        for i, acc in enumerate(accounts):
                            if acc["user"] == a["user"] and acc["pass"] == a["pass"]:
                                accounts[i] = {
                                    "user": a["user"],
                                    "pass": a["pass"],
                                    "added_at": a.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                }
                                print(f"Overwriting account {a['user']}:{a['pass']}")
                                break
                        else:
                            accounts.append({
                                "user": a["user"],
                                "pass": a["pass"],
                                "added_at": a.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                            })
                            print(f"Appending account {a['user']}:{a['pass']}")
        else:
            raise ValueError("Unsupported file format")
        search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
        update_account_table(tab_name, folder_name, search_query)
        messagebox.showinfo("Success", "Accounts imported successfully!", parent=root)
        print("Accounts imported successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid file format or error importing accounts: {str(e)}", parent=root)
        print(f"Error importing accounts: {str(e)}")
        traceback.print_exc()

def import_2fa(tab_name, folder_name):
    print(f"Importing 2FA to {tab_name}/{folder_name}")
    try:
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("JSON files", "*.json")], parent=root)
        if not file_path:
            print("No file selected for 2FA import")
            return
        totp_list = vault["tabs"][tab_name]["folders"][folder_name]["totp"]
        if file_path.endswith('.txt'):
            with open(file_path) as f:
                content = f.read().strip()
                try:
                    decrypted_data = decrypt_data(content, pw)
                    lines = decrypted_data.split("\n")
                except:
                    print("Parsing as unencrypted 2FA file")
                    lines = content.split("\n")
                for line in lines:
                    line = line.strip()
                    if line and ":" in line:
                        name, secret = line.split(":", 1)
                        if name and secret:
                            pyotp.TOTP(secret).now()
                            for i, totp in enumerate(totp_list):
                                if totp["name"] == name and totp["secret"] == secret:
                                    totp_list[i] = {"name": name, "secret": secret, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                                    print(f"Overwriting 2FA {name}:{secret}")
                                    break
                            else:
                                totp_list.append({"name": name, "secret": secret, "added_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
                                print(f"Appending 2FA {name}:{secret}")
        elif file_path.endswith('.json'):
            with open(file_path) as f:
                data = json.load(f)
                totp_entries = data.get("totp", [])
                for t in totp_entries:
                    if "name" in t and "secret" in t:
                        pyotp.TOTP(t["secret"]).now()
                        for i, totp in enumerate(totp_list):
                            if totp["name"] == t["name"] and totp["secret"] == t["secret"]:
                                totp_list[i] = {
                                    "name": t["name"],
                                    "secret": t["secret"],
                                    "added_at": t.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                }
                                print(f"Overwriting 2FA {t['name']}:{t['secret']}")
                                break
                        else:
                            totp_list.append({
                                "name": t["name"],
                                "secret": t["secret"],
                                "added_at": t.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                            })
                            print(f"Appending 2FA {t['name']}:{t['secret']}")
        else:
            raise ValueError("Unsupported file format")
        search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
        update_totp_table(tab_name, folder_name, search_query)
        messagebox.showinfo("Success", "2FA entries imported successfully!", parent=root)
        print("2FA imported successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Invalid file format, Base32 secret, or decryption error: {str(e)}", parent=root)
        print(f"Error importing 2FA: {str(e)}")
        traceback.print_exc()

def export_totp(tab_name, folder_name):
    print(f"Exporting 2FA for {tab_name}/{folder_name}")
    try:
        export_pw = dark_prompt("Verify Password", "Enter master password to export 2FA:", show="*", parent=root)
        if not export_pw:
            print("No password entered for export")
            messagebox.showerror("Error", "Password required to export 2FA", parent=root)
            return
        if os.path.exists(VAULT_FILE):
            try:
                decrypt_data(json.load(open(VAULT_FILE))["data"], export_pw)
            except Exception as e:
                messagebox.showerror("Error", "Incorrect password", parent=root)
                print(f"Password verification failed: {str(e)}")
                return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], parent=root)
        if not file_path:
            print("No file selected for 2FA export")
            return
        totp_data = "\n".join([f"{t['name']}:{t['secret']}" for t in vault["tabs"][tab_name]["folders"][folder_name].get("totp", [])])
        encrypted_data = encrypt_data(totp_data, export_pw)
        with open(file_path, 'w') as f:
            f.write(encrypted_data)
        messagebox.showinfo("Success", "2FA entries exported successfully (encrypted)!", parent=root)
        print("2FA exported successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export 2FA: {str(e)}", parent=root)
        print(f"Error exporting 2FA: {str(e)}")
        traceback.print_exc()

def export_all_2fa():
    print("Exporting all 2FA entries")
    try:
        export_pw = dark_prompt("Verify Password", "Enter master password to export all 2FA:", show="*", parent=root)
        if not export_pw:
            print("No password entered for export")
            messagebox.showerror("Error", "Password required to export all 2FA", parent=root)
            return
        if os.path.exists(VAULT_FILE):
            try:
                decrypt_data(json.load(open(VAULT_FILE))["data"], export_pw)
            except Exception as e:
                messagebox.showerror("Error", "Incorrect password", parent=root)
                print(f"Password verification failed: {str(e)}")
                return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")], parent=root)
        if not file_path:
            print("No file selected for all 2FA export")
            return
        totp_data = []
        for tab_name in vault["tabs"]:
            for folder_name in vault["tabs"][tab_name]["folders"]:
                totp_data.extend([f"{t['name']}:{t['secret']}" for t in vault["tabs"][tab_name]["folders"][folder_name].get("totp", [])])
        encrypted_data = encrypt_data("\n".join(totp_data), export_pw)
        with open(file_path, 'w') as f:
            f.write(encrypted_data)
        messagebox.showinfo("Success", "All 2FA entries exported successfully (encrypted)!", parent=root)
        print("All 2FA exported successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export all 2FA: {str(e)}", parent=root)
        print(f"Error exporting all 2FA: {str(e)}")
        traceback.print_exc()

def export_backup():
    print("Exporting encrypted backup")
    try:
        export_pw = dark_prompt("Verify Password", "Enter master password to export backup:", show="*", parent=root)
        if not export_pw:
            print("No password entered for export")
            messagebox.showerror("Error", "Password required to export backup", parent=root)
            return
        if os.path.exists(VAULT_FILE):
            try:
                decrypt_data(json.load(open(VAULT_FILE))["data"], export_pw)
            except Exception as e:
                messagebox.showerror("Error", "Incorrect password", parent=root)
                print(f"Password verification failed: {str(e)}")
                return
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")], parent=root)
        if not file_path:
            print("No file selected for export")
            return
        with open(file_path, 'w') as f:
            json.dump({"data": encrypt_data(vault, export_pw)}, f)
        messagebox.showinfo("Success", "Encrypted backup exported successfully!", parent=root)
        print("Encrypted backup exported successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to export backup: {str(e)}", parent=root)
        print(f"Error exporting backup: {str(e)}")
        traceback.print_exc()

def import_backup():
    print("Importing encrypted backup")
    try:
        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")], parent=root)
        if not file_path:
            print("No file selected for import")
            return
        with open(file_path) as f:
            data = json.load(f)
            if "data" not in data:
                raise ValueError("Invalid backup format: missing 'data' field")
            imported_vault = decrypt_data(data["data"], pw)
            if "tabs" not in imported_vault:
                raise ValueError("Invalid backup format: missing 'tabs' structure")
            for tab_name, tab_data in imported_vault["tabs"].items():
                if tab_name not in vault["tabs"]:
                    vault["tabs"][tab_name] = {"folders": {}}
                    tab_frame = ttk.Frame(tab_control)
                    tab_control.add(tab_frame, text=f"{tab_name} (0 accounts, 0 2FA)")
                    tab_frames[tab_name] = tab_frame
                    notebook = ttk.Notebook(tab_frame)
                    notebook.pack(expand=True, fill="both")
                    folder_notebooks[tab_name] = notebook
                for folder_name, folder_data in tab_data["folders"].items():
                    if folder_name not in vault["tabs"][tab_name]["folders"]:
                        vault["tabs"][tab_name]["folders"][folder_name] = {"accounts": [], "totp": []}
                        create_folder_frame(tab_name, folder_name)
                    existing_accounts = vault["tabs"][tab_name]["folders"][folder_name]["accounts"]
                    for a in folder_data.get("accounts", []):
                        if "user" in a and "pass" in a:
                            for i, acc in enumerate(existing_accounts):
                                if acc["user"] == a["user"] and acc["pass"] == a["pass"]:
                                    existing_accounts[i] = {
                                        "user": a["user"],
                                        "pass": a["pass"],
                                        "added_at": a.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                    }
                                    print(f"Overwriting account {a['user']}:{a['pass']}")
                                    break
                            else:
                                existing_accounts.append({
                                    "user": a["user"],
                                    "pass": a["pass"],
                                    "added_at": a.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                })
                                print(f"Appending account {a['user']}:{a['pass']}")
                    existing_totp = vault["tabs"][tab_name]["folders"][folder_name]["totp"]
                    for t in folder_data.get("totp", []):
                        if "name" in t and "secret" in t:
                            pyotp.TOTP(t["secret"]).now()
                            for i, totp in enumerate(existing_totp):
                                if totp["name"] == t["name"] and totp["secret"] == t["secret"]:
                                    existing_totp[i] = {
                                        "name": t["name"],
                                        "secret": t["secret"],
                                        "added_at": t.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                    }
                                    print(f"Overwriting 2FA {t['name']}:{t['secret']}")
                                    break
                            else:
                                existing_totp.append({
                                    "name": t["name"],
                                    "secret": t["secret"],
                                    "added_at": t.get("added_at", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                                })
                                print(f"Appending 2FA {t['name']}:{t['secret']}")
                    search_query = search_entries.get((tab_name, folder_name), tk.Entry()).get()
                    update_account_table(tab_name, folder_name, search_query)
                    update_totp_table(tab_name, folder_name, search_query)
            save_vault()
            messagebox.showinfo("Success", "Encrypted backup imported successfully!", parent=root)
            print("Encrypted backup imported successfully")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to import backup (wrong password or invalid format): {str(e)}", parent=root)
        print(f"Error importing backup: {str(e)}")
        traceback.print_exc()

# ---------- Random Password Generator ----------
def generate_password(length, use_upper, use_lower, use_digits, use_special):
    print("Generating password")
    try:
        if not (use_upper or use_lower or use_digits or use_special):
            raise ValueError("At least one character type must be selected")
        chars = ''
        if use_upper:
            chars += string.ascii_uppercase
        if use_lower:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += string.punctuation
        password = ''.join(secrets.choice(chars) for _ in range(length))
        print("Password generated successfully")
        return password
    except Exception as e:
        print(f"Error generating password: {str(e)}")
        raise

def generate_random_password():
    print("Opening random password generator")
    try:
        gen_window = tk.Toplevel(root)
        gen_window.configure(bg="#0b0b0b")
        gen_window.title("Random Password Generator")
        gen_window.geometry("400x300")
        gen_window.resizable(False, False)
        if os.path.exists(ICON_FILE):
            try:
                gen_window.iconbitmap(ICON_FILE)
                icon = tk.PhotoImage(file=ICON_FILE)
                gen_window.iconphoto(True, icon)
                gen_window.update()
                hwnd = gen_window.winfo_id()
                hicon = win32gui.LoadImage(0, ICON_FILE, win32con.IMAGE_ICON, 0, 0, win32con.LR_LOADFROMFILE)
                win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_SMALL, hicon)
                win32gui.SendMessage(hwnd, win32con.WM_SETICON, win32con.ICON_BIG, hicon)
                print(f"Set icon for password generator window")
            except Exception as e:
                print(f"Failed to set generator window icon: {str(e)}")
                traceback.print_exc()

        tk.Label(gen_window, text="Password Length:", bg="#0b0b0b", fg="#e0e0e0", font=("Arial", 10)).pack(pady=5)
        length_entry = tk.Entry(gen_window, bg="#222222", fg="#e0e0e0", insertbackground="#e0e0e0", font=("Arial", 10))
        length_entry.pack(pady=5, padx=10, fill="x")
        length_entry.insert(0, "16")

        use_upper = tk.BooleanVar(value=True)
        use_lower = tk.BooleanVar(value=True)
        use_digits = tk.BooleanVar(value=True)
        use_special = tk.BooleanVar(value=True)

        tk.Checkbutton(gen_window, text="Include Uppercase Letters", variable=use_upper, bg="#0b0b0b", fg="#e0e0e0", selectcolor="#333333", activebackground="#0b0b0b", activeforeground="#e0e0e0", font=("Arial", 10)).pack(anchor="w", padx=10)
        tk.Checkbutton(gen_window, text="Include Lowercase Letters", variable=use_lower, bg="#0b0b0b", fg="#e0e0e0", selectcolor="#333333", activebackground="#0b0b0b", activeforeground="#e0e0e0", font=("Arial", 10)).pack(anchor="w", padx=10)
        tk.Checkbutton(gen_window, text="Include Numbers", variable=use_digits, bg="#0b0b0b", fg="#e0e0e0", selectcolor="#333333", activebackground="#0b0b0b", activeforeground="#e0e0e0", font=("Arial", 10)).pack(anchor="w", padx=10)
        tk.Checkbutton(gen_window, text="Include Special Characters", variable=use_special, bg="#0b0b0b", fg="#e0e0e0", selectcolor="#333333", activebackground="#0b0b0b", activeforeground="#e0e0e0", font=("Arial", 10)).pack(anchor="w", padx=10)

        def gen_pass():
            try:
                length = int(length_entry.get())
                if length < 1:
                    raise ValueError("Length must be at least 1")
                password = generate_password(length, use_upper.get(), use_lower.get(), use_digits.get(), use_special.get())
                pass_entry.delete(0, tk.END)
                pass_entry.insert(0, password)
                print("Password generated and displayed")
            except ValueError as ve:
                messagebox.showerror("Error", str(ve), parent=gen_window)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate password: {str(e)}", parent=gen_window)
                print(f"Error generating password: {str(e)}")
                traceback.print_exc()

        tk.Button(gen_window, text="Generate", command=gen_pass, bg="#1a1a1a", fg="#ffffff", activebackground="#333333", activeforeground="#ffffff", font=("Arial", 10)).pack(pady=10)

        tk.Label(gen_window, text="Generated Password:", bg="#0b0b0b", fg="#e0e0e0", font=("Arial", 10)).pack(pady=5)
        pass_entry = tk.Entry(gen_window, bg="#222222", fg="#e0e0e0", insertbackground="#e0e0e0", font=("Arial", 10))
        pass_entry.pack(pady=5, padx=10, fill="x")

        def copy_pass():
            password = pass_entry.get()
            if password:
                pyperclip.copy(password)
                messagebox.showinfo("Copied", "Password copied to clipboard", parent=gen_window)
                print("Password copied to clipboard")
            else:
                messagebox.showwarning("Warning", "No password to copy", parent=gen_window)
                print("No password to copy")

        tk.Button(gen_window, text="Copy", command=copy_pass, bg="#1a1a1a", fg="#ffffff", activebackground="#333333", activeforeground="#ffffff", font=("Arial", 10)).pack(pady=5)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to open password generator: {str(e)}", parent=root)
        print(f"Error opening password generator: {str(e)}")
        traceback.print_exc()

# ---------- Initial Setup ----------
print("Initializing UI")
try:
    for tab_name in vault["tabs"]:
        tab_frame = ttk.Frame(tab_control)
        tab_control.add(tab_frame, text=f"{tab_name} (0 accounts, 0 2FA)")
        tab_frames[tab_name] = tab_frame
        notebook = ttk.Notebook(tab_frame)
        notebook.pack(expand=True, fill="both")
        folder_notebooks[tab_name] = notebook
        for folder_name in vault["tabs"][tab_name]["folders"]:
            create_folder_frame(tab_name, folder_name)
        update_tab_label(tab_name)
    print("UI initialized successfully")
except Exception as e:
    messagebox.showerror("Error", f"Failed to initialize UI: {str(e)}", parent=root)
    print(f"Error initializing UI: {str(e)}")
    traceback.print_exc()
    root.destroy()
    sys.exit(1)

# ---------- Menu ----------
print("Setting up menu")
try:
    menu = tk.Menu(root, bg="#0b0b0b", fg="#e0e0e0", activebackground="#333333", activeforeground="#ffffff")
    root.config(menu=menu)
    file_menu = tk.Menu(menu, tearoff=0, bg="#0b0b0b", fg="#e0e0e0", activebackground="#333333", activeforeground="#ffffff")
    menu.add_cascade(label="File", menu=file_menu)
    file_menu.add_command(label="Add Tab", command=add_tab)
    file_menu.add_command(
        label="Add Folder in Current Tab",
        command=lambda: add_folder(tab_control.tab(tab_control.select(), "text").split(" (")[0] if tab_control.select() else "Main")
    )
    file_menu.add_separator()
    file_menu.add_command(label="Random Password Generator", command=generate_random_password)
    file_menu.add_separator()
    file_menu.add_command(label="Export All 2FA", command=export_all_2fa)
    file_menu.add_command(label="Export Encrypted Backup", command=export_backup)
    file_menu.add_command(label="Import Encrypted Backup", command=import_backup)
    file_menu.add_separator()
    file_menu.add_command(label="Save & Exit", command=lambda: [save_vault(), root.destroy()])
    print("Menu set up successfully")
except Exception as e:
    messagebox.showerror("Error", f"Failed to set up menu: {str(e)}", parent=root)
    print(f"Error setting up menu: {str(e)}")
    traceback.print_exc()

print("Starting TOTP refresh")
refresh_totp_codes()
print("Entering main loop")
root.mainloop()
print("Main loop exited")