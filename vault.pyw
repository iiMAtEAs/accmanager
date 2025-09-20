import os, json, base64
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk, filedialog
import pyotp
from cryptography.fernet import Fernet
import pyperclip

VAULT_FILE = "vault.json"

# ---------- Encryption helpers ----------
def key_from_password(pw: str) -> bytes:
    return base64.urlsafe_b64encode(pw.encode().ljust(32, b"0")[:32])

def encrypt_data(data, pw):
    f = Fernet(key_from_password(pw))
    return f.encrypt(json.dumps(data).encode()).decode()

def decrypt_data(enc, pw):
    f = Fernet(key_from_password(pw))
    return json.loads(f.decrypt(enc.encode()).decode())

def save_vault(data, pw):
    with open(VAULT_FILE, "w") as fp:
        json.dump({"data": encrypt_data(data, pw)}, fp)

def load_vault(pw):
    if not os.path.exists(VAULT_FILE):
        return {"tabs": {}}
    raw = json.load(open(VAULT_FILE))
    try:
        return decrypt_data(raw["data"], pw)
    except:
        messagebox.showerror("Error", "Incorrect password!")
        return None

# ---------- Login ----------
root = tk.Tk()
root.withdraw()
pw = simpledialog.askstring("Master Password", "Enter master password:", show="*", parent=root)
if not pw:
    raise SystemExit
vault = load_vault(pw)
if vault is None:
    raise SystemExit

# ---------- Main window ----------
root.deiconify()
root.title("Secure Vault")
root.geometry("1000x600")

tab_control = ttk.Notebook(root)
tab_control.pack(expand=1, fill="both")

tab_frames = {}
folder_notebooks = {}
folder_frames = {}
folder_trees = {}

# ---------- Helper functions ----------
def update_account_table(tab_name, folder_name):
    vault_tree, _ = folder_trees[(tab_name, folder_name)]
    vault_tree.delete(*vault_tree.get_children())
    for a in vault["tabs"][tab_name]["folders"][folder_name].get("accounts", []):
        vault_tree.insert("", "end", values=(a["user"], a["pass"]))

def update_totp_table(tab_name, folder_name):
    _, totp_tree = folder_trees[(tab_name, folder_name)]
    totp_tree.delete(*totp_tree.get_children())
    for t in vault["tabs"][tab_name]["folders"][folder_name].get("totp", []):
        totp_tree.insert("", "end", values=(t["name"], pyotp.TOTP(t["secret"]).now()))

def refresh_totp_codes():
    for (tab_name, folder_name) in folder_trees.keys():
        update_totp_table(tab_name, folder_name)
    root.after(30000, refresh_totp_codes)

# ---------- Folder functions ----------
def add_folder(tab_name):
    folder_name = simpledialog.askstring("Folder Name", "Enter folder name:", parent=tab_frames[tab_name])
    if not folder_name: return
    if folder_name in vault["tabs"][tab_name]["folders"]:
        messagebox.showerror("Error", "Folder already exists", parent=root)
        return
    vault["tabs"][tab_name]["folders"][folder_name] = {"accounts": [], "totp": []}
    create_folder_frame(tab_name, folder_name)

def create_folder_frame(tab_name, folder_name):
    notebook = folder_notebooks[tab_name]
    folder_frame = ttk.Frame(notebook)
    notebook.add(folder_frame, text=folder_name)
    folder_frames[(tab_name, folder_name)] = folder_frame

    # Vault table
    vault_tree = ttk.Treeview(folder_frame, columns=("User", "Password"), show="headings")
    vault_tree.heading("User", text="User")
    vault_tree.heading("Password", text="Password")
    vault_tree.pack(expand=True, fill="both")

    # 2FA table
    totp_tree = ttk.Treeview(folder_frame, columns=("Account", "Code"), show="headings")
    totp_tree.heading("Account", text="Account")  # renamed from "Service"
    totp_tree.heading("Code", text="Code")
    totp_tree.pack(expand=True, fill="both")

    # Buttons
    btn_frame = ttk.Frame(folder_frame)
    ttk.Button(btn_frame, text="Add Account", command=lambda: add_account(tab_name, folder_name)).pack(side="left", padx=5, pady=5)
    ttk.Button(btn_frame, text="Add 2FA", command=lambda: add_2fa(tab_name, folder_name)).pack(side="left", padx=5, pady=5)
    ttk.Button(btn_frame, text="Import Accounts", command=lambda: import_accounts(tab_name, folder_name)).pack(side="left", padx=5, pady=5)
    ttk.Button(btn_frame, text="Import 2FA", command=lambda: import_totp(tab_name, folder_name)).pack(side="left", padx=5, pady=5)
    btn_frame.pack()

    folder_trees[(tab_name, folder_name)] = (vault_tree, totp_tree)
    update_account_table(tab_name, folder_name)
    update_totp_table(tab_name, folder_name)

    # Right-click Vault entry
    def vault_right_click(event):
        iid = vault_tree.identify_row(event.y)
        if iid:
            vault_tree.selection_set(iid)
            menu = tk.Menu(root, tearoff=0)
            user, pwd = vault_tree.item(iid)["values"]
            menu.add_command(label="Copy user:pass", command=lambda: pyperclip.copy(f"{user}:{pwd}"))
            menu.add_command(label="Copy user", command=lambda: pyperclip.copy(user))
            menu.add_command(label="Copy pass", command=lambda: pyperclip.copy(pwd))
            menu.add_separator()
            menu.add_command(label="Delete entry", command=lambda: delete_account(tab_name, folder_name, iid))
            menu.tk_popup(event.x_root, event.y_root)
    vault_tree.bind("<Button-3>", vault_right_click)

    # Right-click TOTP entry
    def totp_right_click(event):
        iid = totp_tree.identify_row(event.y)
        if iid:
            totp_tree.selection_set(iid)
            menu = tk.Menu(root, tearoff=0)
            account_name, code = totp_tree.item(iid)["values"]
            folder = vault["tabs"][tab_name]["folders"][folder_name]
            secret = next((t["secret"] for t in folder.get("totp", []) if t["name"] == account_name), "")
            menu.add_command(label="Copy account:code", command=lambda: pyperclip.copy(f"{account_name}:{code}"))
            menu.add_command(label="Copy secret", command=lambda: pyperclip.copy(secret))
            menu.add_command(label="Copy code", command=lambda: pyperclip.copy(code))
            menu.add_separator()
            menu.add_command(label="Delete entry", command=lambda: delete_totp(tab_name, folder_name, iid))
            menu.tk_popup(event.x_root, event.y_root)
    totp_tree.bind("<Button-3>", totp_right_click)

    # Right-click folder tab
    def folder_right_click(event):
        x, y = event.x, event.y
        elem = notebook.identify(x, y)
        if "label" in elem:
            idx = notebook.index("@%d,%d" % (x, y))
            fname = notebook.tab(idx, "text")
            menu = tk.Menu(root, tearoff=0)

            def copy_users():
                folder = vault["tabs"][tab_name]["folders"][fname]
                pyperclip.copy("\n".join([a["user"] for a in folder.get("accounts", [])]))

            def copy_passes():
                folder = vault["tabs"][tab_name]["folders"][fname]
                pyperclip.copy("\n".join([a["pass"] for a in folder.get("accounts", [])]))

            def copy_user_pass():
                folder = vault["tabs"][tab_name]["folders"][fname]
                pyperclip.copy("\n".join([f"{a['user']}:{a['pass']}" for a in folder.get("accounts", [])]))

            def copy_all():
                folder = vault["tabs"][tab_name]["folders"][fname]
                text = "Accounts:\n" + "\n".join([f"{a['user']}:{a['pass']}" for a in folder.get("accounts", [])]) + "\n"
                text += "TOTP:\n" + "\n".join([f"{t['name']}:{t['secret']}" for t in folder.get("totp", [])])
                pyperclip.copy(text)
                messagebox.showinfo("Copied", f"Copied all data in folder '{fname}'")

            def delete_folder():
                if messagebox.askyesno("Delete Folder", f"Delete folder '{fname}'?"):
                    folder_trees.pop((tab_name, fname), None)
                    folder_frames.pop((tab_name, fname), None)
                    vault["tabs"][tab_name]["folders"].pop(fname, None)
                    notebook.forget(idx)

            menu.add_command(label="Copy all", command=copy_all)
            menu.add_command(label="Copy user", command=copy_users)
            menu.add_command(label="Copy pass", command=copy_passes)
            menu.add_command(label="Copy user:pass", command=copy_user_pass)
            menu.add_separator()
            menu.add_command(label="Delete folder", command=delete_folder)
            menu.tk_popup(event.x_root, event.y_root)

    notebook.bind("<Button-3>", folder_right_click)

# ---------- Account / 2FA ----------
def add_account(tab_name, folder_name):
    folder_frame = folder_frames[(tab_name, folder_name)]
    user = simpledialog.askstring("Username", "Enter username:", parent=folder_frame)
    if not user: return
    pwd = simpledialog.askstring("Password", "Enter password:", parent=folder_frame, show="*")
    if not pwd: return
    vault["tabs"][tab_name]["folders"][folder_name]["accounts"].append({"user": user, "pass": pwd})
    update_account_table(tab_name, folder_name)

def delete_account(tab_name, folder_name, iid):
    vault_tree, _ = folder_trees[(tab_name, folder_name)]
    user, pwd = vault_tree.item(iid)["values"]
    vault["tabs"][tab_name]["folders"][folder_name]["accounts"] = [
        a for a in vault["tabs"][tab_name]["folders"][folder_name]["accounts"]
        if not(a["user"]==user and a["pass"]==pwd)
    ]
    update_account_table(tab_name, folder_name)

def add_2fa(tab_name, folder_name):
    folder_frame = folder_frames[(tab_name, folder_name)]
    name = simpledialog.askstring("Account", "Account name:", parent=folder_frame)
    if not name: return
    secret = simpledialog.askstring("Base32 Secret", "Enter Base32 secret:", parent=folder_frame)
    if not secret: return
    vault["tabs"][tab_name]["folders"][folder_name]["totp"].append({"name": name, "secret": secret})
    update_totp_table(tab_name, folder_name)

def delete_totp(tab_name, folder_name, iid):
    _, totp_tree = folder_trees[(tab_name, folder_name)]
    name = totp_tree.item(iid)["values"][0]
    vault["tabs"][tab_name]["folders"][folder_name]["totp"] = [
        t for t in vault["tabs"][tab_name]["folders"][folder_name]["totp"] if t["name"] != name
    ]
    update_totp_table(tab_name, folder_name)

# ---------- Import ----------
def import_accounts(tab_name, folder_name):
    file_path = filedialog.askopenfilename(
        filetypes=[("JSON and Text files", "*.json *.txt"), ("JSON files", "*.json"), ("Text files", "*.txt")],
        parent=root
    )
    if not file_path: return

    folder = vault["tabs"][tab_name]["folders"][folder_name]

    if file_path.endswith(".json"):
        with open(file_path) as f:
            data = json.load(f)
            for a in data.get("accounts", []):
                folder["accounts"].append(a)
    elif file_path.endswith(".txt"):
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    user, pwd = line.split(":", 1)
                    folder["accounts"].append({"user": user, "pass": pwd})

    update_account_table(tab_name, folder_name)

def import_totp(tab_name, folder_name):
    file_path = filedialog.askopenfilename(filetypes=[("JSON files","*.json")], parent=root)
    if not file_path: return
    with open(file_path) as f:
        data = json.load(f)
        for t in data.get("totp", []):
            vault["tabs"][tab_name]["folders"][folder_name]["totp"].append(t)
    update_totp_table(tab_name, folder_name)

# ---------- Backup / Restore ----------
def backup_vault():
    file_path = filedialog.asksaveasfilename(defaultextension=".vault", filetypes=[("Vault Backup", "*.vault")])
    if not file_path: return
    with open(file_path, "w") as f:
        f.write(encrypt_data(vault, pw))
    messagebox.showinfo("Backup", "Vault backup saved successfully.")

def restore_vault():
    file_path = filedialog.askopenfilename(filetypes=[("Vault Backup", "*.vault")])
    if not file_path: return
    with open(file_path) as f:
        try:
            global vault
            vault = decrypt_data(f.read(), pw)
            messagebox.showinfo("Restore", "Vault restored successfully. Restart to apply changes.")
        except:
            messagebox.showerror("Error", "Failed to restore backup. Incorrect password or corrupted file.")

# ---------- Tab functions ----------
def add_tab():
    tab_name = simpledialog.askstring("Tab Name", "Enter tab name:", parent=root)
    if not tab_name: return
    if tab_name in vault["tabs"]:
        messagebox.showerror("Error", "Tab already exists", parent=root)
        return
    tab_frame = ttk.Frame(tab_control)
    tab_control.add(tab_frame, text=tab_name)
    tab_frames[tab_name] = tab_frame
    vault["tabs"][tab_name] = {"folders": {}}
    notebook = ttk.Notebook(tab_frame)
    notebook.pack(expand=True, fill="both")
    folder_notebooks[tab_name] = notebook

def tab_right_click(event):
    x, y = event.x, event.y
    elem = tab_control.identify(x, y)
    if "label" in elem:
        idx = tab_control.index("@%d,%d" % (x, y))
        tab_name = tab_control.tab(idx, "text")
        menu = tk.Menu(root, tearoff=0)
        menu.add_command(label="Copy all", command=lambda: copy_tab(tab_name))
        menu.add_command(label="Delete tab", command=lambda: delete_tab(tab_name))
        menu.tk_popup(event.x_root, event.y_root)

def copy_tab(tab_name):
    text = ""
    for folder_name in vault["tabs"][tab_name]["folders"]:
        folder = vault["tabs"][tab_name]["folders"][folder_name]
        text += f"Folder: {folder_name}\n"
        text += "Accounts:\n" + "\n".join([f"{a['user']}:{a['pass']}" for a in folder.get("accounts", [])]) + "\n"
        text += "TOTP:\n" + "\n".join([f"{t['name']}:{t['secret']}" for t in folder.get("totp", [])]) + "\n\n"
    pyperclip.copy(text)
    messagebox.showinfo("Copied", f"Copied all contents of tab '{tab_name}'")

def delete_tab(tab_name):
    if messagebox.askyesno("Delete Tab", f"Delete tab '{tab_name}'?"):
        for folder_name in list(vault["tabs"][tab_name]["folders"].keys()):
            folder_trees.pop((tab_name, folder_name), None)
            folder_frames.pop((tab_name, folder_name), None)
        vault["tabs"].pop(tab_name, None)
        tab_id = tab_control.index(tab_frames[tab_name])
        tab_control.forget(tab_id)
        tab_frames.pop(tab_name)
        folder_notebooks.pop(tab_name, None)

tab_control.bind("<Button-3>", tab_right_click)

# ---------- Initial tab ----------
initial_tab = simpledialog.askstring("Tab Name", "Enter tab name:", initialvalue="Main", parent=root)
if not initial_tab:
    initial_tab = "Main"
if initial_tab not in vault["tabs"]:
    vault["tabs"][initial_tab] = {"folders": {}}
tab_frames[initial_tab] = ttk.Frame(tab_control)
tab_control.add(tab_frames[initial_tab], text=initial_tab)
folder_notebooks[initial_tab] = ttk.Notebook(tab_frames[initial_tab])
folder_notebooks[initial_tab].pack(expand=True, fill="both")

# ---------- Menu ----------
menu = tk.Menu(root)
root.config(menu=menu)
file_menu = tk.Menu(menu, tearoff=0)
menu.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Add Tab", command=add_tab)
file_menu.add_command(label="Add Folder in Current Tab",
                      command=lambda: add_folder(tab_control.tab(tab_control.select(), "text")))
file_menu.add_command(label="Backup Vault", command=backup_vault)
file_menu.add_command(label="Restore Vault", command=restore_vault)
file_menu.add_command(label="Save & Exit", command=lambda:[save_vault(vault, pw), root.destroy()])

refresh_totp_codes()
root.mainloop()
