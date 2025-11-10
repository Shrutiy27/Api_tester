"""
API Tester - Fixed version (no private attributes, no early app_vars use)
Requirements:
    pip install requests pyperclip customtkinter
Run:
    python main.py
"""

import os
import json
import time
import threading
import requests
import pyperclip
import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

# ---------------- Config ----------------
ctk.set_default_color_theme("blue")
ctk.set_appearance_mode("System")

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
RESP_DIR = os.path.join(DATA_DIR, "responses")
HISTORY_FILE = os.path.join(DATA_DIR, "history.json")
COLLECTIONS_FILE = os.path.join(DATA_DIR, "collections.json")
os.makedirs(RESP_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# ---------------- Helpers ----------------
def now_ts(fmt="%Y-%m-%d %H:%M:%S"):
    return time.strftime(fmt)

def sanitize_filename(s):
    keep = "-_.() abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(c if c in keep else "_" for c in s)[:140]

def pretty_json(text):
    try:
        obj = json.loads(text)
        return json.dumps(obj, indent=2, ensure_ascii=False)
    except Exception:
        return text

def load_json_file(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ---------------- History & Collections ----------------
def load_history():
    return load_json_file(HISTORY_FILE, [])

def save_history(history):
    save_json_file(HISTORY_FILE, history)

def save_history_item(item):
    h = load_history()
    h.insert(0, item)
    save_history(h[:1000])

def save_response_to_file(item):
    safe_url = sanitize_filename(item.get("url",""))[:60]
    fname = f"{time.strftime('%Y%m%d_%H%M%S')}_{item.get('method')}_{safe_url}.txt"
    path = os.path.join(RESP_DIR, fname)
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"Timestamp: {item.get('timestamp')}\nURL: {item.get('url')}\nMethod: {item.get('method')}\nStatus: {item.get('status')}\nElapsed: {item.get('elapsed')}\n\n--- REQUEST HEADERS ---\n")
        f.write(json.dumps(item.get("request_headers", {}), indent=2))
        f.write("\n\n--- REQUEST BODY ---\n")
        f.write(item.get("request_body",""))
        f.write("\n\n--- RESPONSE HEADERS ---\n")
        f.write(json.dumps(item.get("response_headers", {}), indent=2))
        f.write("\n\n--- RESPONSE BODY ---\n")
        f.write(item.get("response_body",""))
    return path

def load_collections():
    return load_json_file(COLLECTIONS_FILE, [])

def save_collections(data):
    save_json_file(COLLECTIONS_FILE, data)

# ---------------- Request Execution (threaded) ----------------
def run_request(method, url, headers_text, body_text, ui_vars):
    start = time.time()
    try:
        headers = {}
        headers_text = headers_text.strip()
        if headers_text:
            try:
                headers = json.loads(headers_text)
            except Exception:
                for line in headers_text.splitlines():
                    if ":" in line:
                        k,v = line.split(":",1)
                        headers[k.strip()] = v.strip()

        json_body = None
        data_body = None
        if body_text.strip():
            try:
                json_body = json.loads(body_text)
            except Exception:
                data_body = body_text.encode("utf-8")

        if ui_vars.get('auth_type') == "Bearer" and ui_vars.get('bearer_token'):
            headers["Authorization"] = f"Bearer {ui_vars['bearer_token']}"
        elif ui_vars.get('auth_type') == "Basic" and ui_vars.get('basic_user') is not None:
            import base64
            token = f"{ui_vars.get('basic_user')}:{ui_vars.get('basic_pass')}"
            headers["Authorization"] = "Basic " + base64.b64encode(token.encode()).decode()

        try:
            timeout = float(ui_vars.get('timeout', 30))
        except:
            timeout = 30.0
        allow_redirects = ui_vars.get('follow_redirects', True)

        def before():
            ui_vars['status_label'].configure(text="Status: Sending...", text_color="orange")
            ui_vars['time_label'].configure(text="-")
        ui_vars['root'].after(0, before)

        resp = requests.request(method, url, headers=headers or None, json=json_body, data=data_body, timeout=timeout, allow_redirects=allow_redirects)
        elapsed = time.time() - start
        resp_text_pretty = pretty_json(resp.text)
        response_headers = dict(resp.headers)

        item = {
            "timestamp": now_ts(),
            "method": method,
            "url": url,
            "request_headers": headers,
            "request_body": body_text,
            "status": resp.status_code,
            "response_headers": response_headers,
            "response_body": resp_text_pretty,
            "elapsed": round(elapsed, 3)
        }
        save_history_item(item)
        saved_path = save_response_to_file(item)

        def success():
            ui_vars['status_label'].configure(text=f"Status: {resp.status_code}", text_color=("green" if 200 <= resp.status_code < 300 else "orange" if 300 <= resp.status_code < 400 else "red"))
            ui_vars['time_label'].configure(text=f"{elapsed:.2f}s")
            ui_vars['resp_body'].configure(state="normal")
            ui_vars['resp_body'].delete("1.0", "end")
            ui_vars['resp_body'].insert("1.0", resp_text_pretty)
            ui_vars['resp_body'].configure(state="disabled")
            ui_vars['resp_headers'].configure(state="normal")
            ui_vars['resp_headers'].delete("1.0", "end")
            ui_vars['resp_headers'].insert("1.0", json.dumps(response_headers, indent=2))
            ui_vars['resp_headers'].configure(state="disabled")
            ui_vars['last_saved_path'] = saved_path
            refresh_history_listbox(ui_vars)
        ui_vars['root'].after(0, success)

    except Exception as e:
        def error():
            ui_vars['status_label'].configure(text="Status: Error", text_color="red")
            ui_vars['time_label'].configure(text="-")
            ui_vars['resp_body'].configure(state="normal")
            ui_vars['resp_body'].delete("1.0", "end")
            ui_vars['resp_body'].insert("1.0", f"Error: {e}")
            ui_vars['resp_body'].configure(state="disabled")
        ui_vars['root'].after(0, error)

# ---------------- UI helpers ----------------
def new_request_tab(tabview, title="Request"):
    app_state['tab_index'] = app_state.get('tab_index', 0) + 1
    tab_name = f"{title} {app_state['tab_index']}"
    tabview.add(tab_name)
    frame = tabview.tab(tab_name)

    method = ctk.CTkOptionMenu(frame, values=["GET","POST","PUT","PATCH","DELETE"], width=90)
    method.set("GET")
    method.grid(row=0, column=0, padx=8, pady=8, sticky="w")

    url_entry = ctk.CTkEntry(frame, placeholder_text="https://api.example.com/endpoint", width=720)
    url_entry.grid(row=0, column=1, padx=8, pady=8, sticky="we", columnspan=3)

    headers_label = ctk.CTkLabel(frame, text="Headers")
    headers_label.grid(row=1, column=0, sticky="nw", padx=8)
    headers_txt = ctk.CTkTextbox(frame, width=480, height=100)
    headers_txt.grid(row=1, column=1, padx=8, pady=4, sticky="nsew")

    body_label = ctk.CTkLabel(frame, text="Body")
    body_label.grid(row=1, column=2, sticky="nw", padx=8)
    body_txt = ctk.CTkTextbox(frame, width=350, height=100)
    body_txt.grid(row=1, column=3, padx=8, pady=4, sticky="nsew")

    send_btn = ctk.CTkButton(frame, text="Send", width=120)
    send_btn.grid(row=2, column=3, pady=8, padx=8, sticky="e")

    tab_meta = {
        "name": tab_name,
        "method": method,
        "url": url_entry,
        "headers": headers_txt,
        "body": body_txt,
        "send_btn": send_btn
    }
    return tab_meta

def get_current_request_meta(tabview):
    active = tabview.get()
    return app_state['tabs'].get(active)

def create_request_action(app_vars):
    tabview = app_vars['requests_tabview']
    meta = new_request_tab(tabview, "Request")
    def send_for_tab():
        method = meta['method'].get()
        url = meta['url'].get().strip()
        headers_text = meta['headers'].get("1.0", "end").strip()
        body_text = meta['body'].get("1.0", "end").strip()
        if not url:
            messagebox.showwarning("Missing URL", "Enter a URL first.")
            return
        ui_vars = {
            'root': app_vars['root'],
            'resp_body': app_vars['resp_body'],
            'resp_headers': app_vars['resp_headers'],
            'status_label': app_vars['status_label'],
            'time_label': app_vars['time_label'],
            'timeout': app_vars['timeout_var'].get(),
            'follow_redirects': app_vars['follow_var'].get(),
            'auth_type': app_vars['auth_type_var'].get(),
            'bearer_token': app_vars['bearer_var'].get(),
            'basic_user': app_vars['basic_user_var'].get(),
            'basic_pass': app_vars['basic_pass_var'].get(),
            'last_saved_path': None
        }
        threading.Thread(target=run_request, args=(method, url, headers_text, body_text, ui_vars), daemon=True).start()
    meta['send_btn'].configure(command=send_for_tab)
    app_state['tabs'][meta['name']] = meta
    app_vars['requests_tabview'].set(meta['name'])

def remove_current_request_tab(app_vars):
    tabview = app_vars['requests_tabview']
    cur = tabview.get()
    if len(app_state['tabs']) <= 1:
        messagebox.showinfo("Cannot remove", "At least one request tab required.")
        return
    if cur in app_state['tabs']:
        del app_state['tabs'][cur]
    try:
        tabview.remove(cur)
    except Exception:
        pass

# ---------------- History UI ----------------
def refresh_history_listbox(app_vars, filter_text=""):
    lb = app_vars['history_listbox']
    lb.delete(0, tk.END)
    hist = load_history()
    filtered = []
    if filter_text:
        f = filter_text.lower()
        for item in hist:
            if f in item.get('url','').lower() or f in str(item.get('status','')) or f in item.get('method','').lower():
                filtered.append(item)
    else:
        filtered = hist
    for item in filtered:
        label = f"[{item.get('timestamp')}] {item.get('method')} {shorten(item.get('url', ''), 60)} → {item.get('status')}"
        lb.insert(tk.END, label)
    app_vars['history_cache'] = filtered

def shorten(s, length=60):
    return (s[:length-3] + "...") if len(s) > length else s

def on_history_select(evt, app_vars):
    lb = app_vars['history_listbox']
    sel = lb.curselection()
    if not sel:
        return
    idx = sel[0]
    hist = app_vars.get('history_cache', [])
    if idx >= len(hist):
        return
    item = hist[idx]
    app_vars['resp_body'].configure(state="normal")
    app_vars['resp_body'].delete("1.0", "end")
    app_vars['resp_body'].insert("1.0", item.get('response_body',''))
    app_vars['resp_body'].configure(state="disabled")
    app_vars['resp_headers'].configure(state="normal")
    app_vars['resp_headers'].delete("1.0", "end")
    app_vars['resp_headers'].insert("1.0", json.dumps(item.get('response_headers',{}), indent=2))
    app_vars['resp_headers'].configure(state="disabled")
    app_vars['status_label'].configure(text=f"Status: {item.get('status')}")
    app_vars['time_label'].configure(text=f"{item.get('elapsed')}s")

def clear_history_action(app_vars):
    if not messagebox.askyesno("Clear history", "Delete all history? This cannot be undone."):
        return
    save_history([])
    refresh_history_listbox(app_vars)

def export_history_action(app_vars):
    hist = load_history()
    if not hist:
        messagebox.showinfo("No history", "History is empty.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
    if path:
        save_json_file(path, hist)
        messagebox.showinfo("Saved", f"Exported history to:\n{path}")

# ---------------- Collections ----------------
def save_current_to_collection(app_vars):
    tab_name = app_vars['requests_tabview'].get()
    meta = app_state['tabs'].get(tab_name)
    if not meta:
        messagebox.showwarning("No tab", "No request tab selected.")
        return
    name = simpledialog.askstring("Collection name", "Enter a name for this saved request:")
    if not name:
        return
    collections = load_collections()
    entry = {
        "name": name,
        "method": meta['method'].get(),
        "url": meta['url'].get(),
        "headers": meta['headers'].get("1.0","end").strip(),
        "body": meta['body'].get("1.0","end").strip()
    }
    collections.insert(0, entry)
    save_collections(collections)
    refresh_collections_listbox(app_vars)

def refresh_collections_listbox(app_vars):
    lb = app_vars['collections_listbox']
    lb.delete(0, tk.END)
    cols = load_collections()
    for c in cols:
        lb.insert(tk.END, f"{c.get('name')} — {c.get('method')} {shorten(c.get('url',''),60)}")
    app_vars['collections_cache'] = cols

def on_collection_select(evt, app_vars):
    sel = app_vars['collections_listbox'].curselection()
    if not sel:
        return
    idx = sel[0]
    cols = app_vars.get('collections_cache', [])
    if idx >= len(cols): return
    item = cols[idx]
    tab_name = app_vars['requests_tabview'].get()
    meta = app_state['tabs'].get(tab_name)
    if not meta:
        return
    meta['method'].set(item.get('method','GET'))
    meta['url'].delete(0, tk.END)
    meta['url'].insert(0, item.get('url',''))
    meta['headers'].delete("1.0", "end")
    meta['headers'].insert("1.0", item.get('headers',''))
    meta['body'].delete("1.0", "end")
    meta['body'].insert("1.0", item.get('body',''))

def delete_collection(app_vars):
    sel = app_vars['collections_listbox'].curselection()
    if not sel:
        return
    idx = sel[0]
    cols = load_collections()
    if idx >= len(cols): return
    if not messagebox.askyesno("Delete", f"Delete collection: {cols[idx].get('name')}?"):
        return
    cols.pop(idx)
    save_collections(cols)
    refresh_collections_listbox(app_vars)

# ---------------- Copy / Export response ----------------
def copy_response(app_vars):
    text = app_vars['resp_body'].get("1.0", "end").strip()
    if not text:
        messagebox.showinfo("Empty", "Response body empty.")
        return
    pyperclip.copy(text)
    messagebox.showinfo("Copied", "Response body copied to clipboard.")

def export_response(app_vars):
    text = app_vars['resp_body'].get("1.0", "end").strip()
    if not text:
        messagebox.showinfo("Empty", "Response body empty.")
        return
    path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text","*.txt"),("JSON","*.json")])
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        messagebox.showinfo("Saved", f"Saved to:\n{path}")

def resp_body_pretty(app_vars):
    s = app_vars['resp_body'].get("1.0", "end").strip()
    if not s:
        return
    pretty = pretty_json(s)
    app_vars['resp_body'].configure(state="normal")
    app_vars['resp_body'].delete("1.0", "end")
    app_vars['resp_body'].insert("1.0", pretty)
    app_vars['resp_body'].configure(state="disabled")

def open_last_saved(app_vars):
    path = app_vars.get('last_saved_path')
    if not path or not os.path.exists(path):
        messagebox.showinfo("Not found", "No saved response file found for the last request.")
        return
    try:
        os.startfile(path)
    except Exception as e:
        messagebox.showerror("Open failed", str(e))

# ---------------- Build Main UI ----------------
def build_ui():
    root = ctk.CTk()
    root.title("API Tester — Pro")
    root.geometry("1100x700")
    root.minsize(1000, 600)

    left = ctk.CTkFrame(root, width=300)
    left.pack(side="left", fill="y", padx=12, pady=12)

    ctk.CTkLabel(left, text="History", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(8,4))
    hist_search = ctk.CTkEntry(left, placeholder_text="Search history (url, status, method)")
    hist_search.pack(fill="x", padx=8)

    history_frame = ctk.CTkScrollableFrame(left, height=280)
    history_frame.pack(fill="both", expand=False, padx=8, pady=8)
    history_listbox = tk.Listbox(history_frame, bd=0, highlightthickness=0)
    history_listbox.pack(fill="both", expand=True, padx=4, pady=4)

    h_btn_frame = ctk.CTkFrame(left)
    h_btn_frame.pack(fill="x", padx=8, pady=(4,8))
    ctk.CTkButton(h_btn_frame, text="Refresh", command=lambda: refresh_history_listbox(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(h_btn_frame, text="Export", command=lambda: export_history_action(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(h_btn_frame, text="Clear", command=lambda: clear_history_action(app_vars)).pack(side="left", padx=6)

    ctk.CTkLabel(left, text="Collections", font=ctk.CTkFont(size=16)).pack(pady=(6,2))
    col_frame = ctk.CTkScrollableFrame(left, height=120)
    col_frame.pack(fill="both", expand=False, padx=8, pady=4)
    collections_listbox = tk.Listbox(col_frame, bd=0, highlightthickness=0)
    collections_listbox.pack(fill="both", expand=True, padx=4, pady=4)

    col_btn_frame = ctk.CTkFrame(left)
    col_btn_frame.pack(fill="x", padx=8, pady=(4,8))
    ctk.CTkButton(col_btn_frame, text="Save", command=lambda: save_current_to_collection(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(col_btn_frame, text="Delete", command=lambda: delete_collection(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(col_btn_frame, text="Refresh", command=lambda: refresh_collections_listbox(app_vars)).pack(side="left", padx=6)

    right = ctk.CTkFrame(root)
    right.pack(side="right", fill="both", expand=True, padx=12, pady=12)

    top_ctrl = ctk.CTkFrame(right)
    top_ctrl.pack(fill="x", padx=8, pady=(2,8))

    theme_menu = ctk.CTkOptionMenu(top_ctrl, values=["Light","Dark","System"], width=120)
    theme_menu.set("System")
    theme_menu.grid(row=0,column=0,padx=8)
    def on_theme_change(choice):
        ctk.set_appearance_mode(choice)
    theme_menu.configure(command=on_theme_change)

    ctk.CTkButton(top_ctrl, text="New Tab", width=100, command=lambda: create_request_action(app_vars)).grid(row=0,column=1,padx=6)
    ctk.CTkButton(top_ctrl, text="Remove Tab", width=110, command=lambda: remove_current_request_tab(app_vars)).grid(row=0,column=2,padx=6)

    ctk.CTkLabel(top_ctrl, text="Auth:").grid(row=0,column=3,padx=(20,4))
    auth_type = ctk.CTkOptionMenu(top_ctrl, values=["None","Bearer","Basic"], width=80)
    auth_type.set("None")
    auth_type.grid(row=0,column=4,padx=6)
    bearer_entry = ctk.CTkEntry(top_ctrl, placeholder_text="Bearer token (if using)", width=240)
    bearer_entry.grid(row=0,column=5,padx=6)
    basic_user = ctk.CTkEntry(top_ctrl, placeholder_text="Basic user", width=120)
    basic_pass = ctk.CTkEntry(top_ctrl, placeholder_text="Basic pass", width=120, show="*")
    basic_user.grid(row=0,column=6,padx=6)
    basic_pass.grid(row=0,column=7,padx=6)

    timeout_var = ctk.CTkEntry(top_ctrl, width=80)
    timeout_var.insert(0,"30")
    timeout_var.grid(row=0,column=8,padx=(12,6))
    ctk.CTkLabel(top_ctrl, text="sec").grid(row=0,column=9)
    follow_var = tk.BooleanVar(value=True)
    follow_cb = ctk.CTkCheckBox(top_ctrl, text="Follow Redirects", variable=follow_var)
    follow_cb.grid(row=0,column=10,padx=8)

    status_label = ctk.CTkLabel(right, text="Status: -")
    status_label.pack(anchor="w", padx=16)
    time_label = ctk.CTkLabel(right, text="Time: -")
    time_label.pack(anchor="w", padx=16)

    requests_tabview = ctk.CTkTabview(right, width=800, height=220)
    requests_tabview.pack(fill="x", padx=8, pady=6)

    # initialize state
    app_state['tabs'] = {}
    app_state['tab_index'] = 0

    first_meta = new_request_tab(requests_tabview, "Request")
    first_meta['send_btn'].configure(command=lambda: create_request_action_send(first_meta, app_vars))
    app_state['tabs'][first_meta['name']] = first_meta
    requests_tabview.set(first_meta['name'])

    resp_frame = ctk.CTkFrame(right)
    resp_frame.pack(fill="both", expand=True, padx=8, pady=8)

    resp_tab = ctk.CTkTabview(resp_frame)
    resp_tab.pack(fill="both", expand=True, padx=8, pady=8)
    resp_tab.add("Body")
    resp_tab.add("Headers")
    resp_tab.add("Raw")

    resp_body = ctk.CTkTextbox(resp_tab.tab("Body"), width=800, height=240)
    resp_body.pack(fill="both", expand=True, padx=8, pady=8)
    resp_body.configure(state="disabled")

    resp_headers = ctk.CTkTextbox(resp_tab.tab("Headers"), width=800, height=240)
    resp_headers.pack(fill="both", expand=True, padx=8, pady=8)
    resp_headers.configure(state="disabled")

    resp_raw = ctk.CTkTextbox(resp_tab.tab("Raw"), width=800, height=240)
    resp_raw.pack(fill="both", expand=True, padx=8, pady=8)
    resp_raw.configure(state="disabled")

    resp_btn_frame = ctk.CTkFrame(right)
    resp_btn_frame.pack(fill="x", padx=8, pady=(0,8))
    ctk.CTkButton(resp_btn_frame, text="Pretty JSON", command=lambda: resp_body_pretty(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(resp_btn_frame, text="Copy Body", command=lambda: copy_response(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(resp_btn_frame, text="Export", command=lambda: export_response(app_vars)).pack(side="left", padx=6)
    ctk.CTkButton(resp_btn_frame, text="Open saved file", command=lambda: open_last_saved(app_vars)).pack(side="left", padx=6)

    app_vars_local = {
        'root': root,
        'requests_tabview': requests_tabview,
        'resp_body': resp_body,
        'resp_headers': resp_headers,
        'resp_raw': resp_raw,
        'status_label': status_label,
        'time_label': time_label,
        'history_listbox': history_listbox,
        'collections_listbox': collections_listbox,
        'timeout_var': timeout_var,
        'follow_var': follow_var,
        'auth_type_var': auth_type,
        'bearer_var': bearer_entry,
        'basic_user_var': basic_user,
        'basic_pass_var': basic_pass,
        'history_cache': [],
        'last_saved_path': None
    }

    # connect search and listbox callbacks (these refer to app_vars, so do not call until returned)
    hist_search.bind("<KeyRelease>", lambda e: refresh_history_listbox(app_vars, hist_search.get().strip()))
    history_listbox.bind("<<ListboxSelect>>", lambda e: on_history_select(e, app_vars))
    collections_listbox.bind("<<ListboxSelect>>", lambda e: on_collection_select(e, app_vars))

    return root, app_vars_local

# ---------------- helpers that need app_vars ----------------
def create_request_action_send(meta, app_vars):
    method = meta['method'].get()
    url = meta['url'].get().strip()
    headers_text = meta['headers'].get("1.0", "end").strip()
    body_text = meta['body'].get("1.0", "end").strip()
    if not url:
        messagebox.showwarning("Missing URL", "Please enter URL.")
        return
    ui_vars = {
        'root': app_vars['root'],
        'resp_body': app_vars['resp_body'],
        'resp_headers': app_vars['resp_headers'],
        'status_label': app_vars['status_label'],
        'time_label': app_vars['time_label'],
        'timeout': app_vars['timeout_var'].get(),
        'follow_redirects': app_vars['follow_var'].get(),
        'auth_type': app_vars['auth_type_var'].get(),
        'bearer_token': app_vars['bearer_var'].get(),
        'basic_user': app_vars['basic_user_var'].get(),
        'basic_pass': app_vars['basic_pass_var'].get(),
        'last_saved_path': None
    }
    threading.Thread(target=run_request, args=(method, url, headers_text, body_text, ui_vars), daemon=True).start()

def create_request_action(app_vars):
    tabview = app_vars['requests_tabview']
    meta = new_request_tab(tabview, "Request")
    meta['send_btn'].configure(command=lambda: create_request_action_send(meta, app_vars))
    app_state['tabs'][meta['name']] = meta
    tabview.set(meta['name'])

def remove_current_request_tab(app_vars):
    tabview = app_vars['requests_tabview']
    cur = tabview.get()
    if len(app_state['tabs']) <= 1:
        messagebox.showinfo("Cannot remove", "At least one request tab required.")
        return
    if cur in app_state['tabs']:
        del app_state['tabs'][cur]
    try:
        tabview.remove(cur)
    except Exception:
        pass

# ---------------- small UI helpers ----------------
def resp_body_pretty(app_vars):
    s = app_vars['resp_body'].get("1.0", "end").strip()
    if not s:
        return
    pretty = pretty_json(s)
    app_vars['resp_body'].configure(state="normal")
    app_vars['resp_body'].delete("1.0", "end")
    app_vars['resp_body'].insert("1.0", pretty)
    app_vars['resp_body'].configure(state="disabled")

# ---------------- App state & start ----------------
app_state = {"tabs": {}, "tab_index": 0}
root, app_vars = build_ui()

# now that app_vars exists, we can wire up actions that use it:
refresh_history_listbox(app_vars)
refresh_collections_listbox(app_vars)

# connect leftover buttons that reference app_vars
# (these were added to the UI earlier referencing app_vars in their command lambdas)
# Start the app
if __name__ == "__main__":
    root.mainloop()
