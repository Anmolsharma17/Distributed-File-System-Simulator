import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import hashlib
import random
from multiprocessing import Process, Queue, Value
import time
import os
from cryptography.fernet import Fernet  # Requires `pip install cryptography`

# Simulated Node Class
class Node:
    def __init__(self, node_id, active=True):
        self.node_id = node_id
        self.active = active
        self.storage = {}

    def store(self, filename_chunk, data, checksum):
        if self.active:
            self.storage[filename_chunk] = (data, checksum)
            print(f"Node {self.node_id}: Stored {filename_chunk}")
            return True
        return False

    def retrieve(self, filename_chunk):
        if self.active and filename_chunk in self.storage:
            data, checksum = self.storage[filename_chunk]
            if hashlib.sha256(data).hexdigest() == checksum:
                print(f"Node {self.node_id}: Retrieved {filename_chunk}")
                return data
            else:
                print(f"Node {self.node_id}: Checksum mismatch for {filename_chunk}")
        print(f"Node {self.node_id}: {filename_chunk} not found or inactive")
        return None

    def delete(self, filename_chunk):
        if self.active and filename_chunk in self.storage:
            del self.storage[filename_chunk]
            return True
        return False

    def fail(self):
        self.active = False

    def recover(self):
        self.active = True

# File Comparison Function
def compare_files(original_path, retrieved_path, verbose=True, max_differences=5):
    try:
        with open(original_path, 'rb') as f1, open(retrieved_path, 'rb') as f2:
            data1 = f1.read()
            data2 = f2.read()

        if data1 == data2:
            if verbose:
                print("Files are identical.")
            return {"identical": True, "differences": [], "total_differences": 0}

        differences = []
        total_differences = 0
        try:
            lines1 = data1.decode('utf-8').splitlines()
            lines2 = data2.decode('utf-8').splitlines()
            max_lines = max(len(lines1), len(lines2))
            for i in range(max_lines):
                line1 = lines1[i] if i < len(lines1) else "(no more lines)"
                line2 = lines2[i] if i < len(lines2) else "(no more lines)"
                if line1 != line2:
                    total_differences += 1
                    if len(differences) < max_differences:
                        differences.append((i + 1, line1, line2))
        except UnicodeDecodeError:
            for i, (b1, b2) in enumerate(zip(data1, data2)):
                if b1 != b2:
                    total_differences += 1
                    if len(differences) < max_differences:
                        differences.append((i, b1, b2))
                    break
            if len(data1) != len(data2):
                total_differences += 1
                if len(differences) < max_differences:
                    differences.append((min(len(data1), len(data2)), f"Length mismatch: {len(data1)} vs {len(data2)}", ""))

        return {"identical": False, "differences": differences, "total_differences": total_differences}

    except FileNotFoundError as e:
        print(f"Error: One or both files not found - {e}")
        return {"identical": False, "differences": [], "total_differences": 0}
    except Exception as e:
        print(f"An error occurred: {e}")
        return {"identical": False, "differences": [], "total_differences": 0}

# Distributed File System
class DFS:
    def __init__(self, num_nodes=3, replication_factor=2, chunk_size=1024):
        self.nodes = [Node(i) for i in range(num_nodes)]
        self.replication_factor = min(replication_factor, num_nodes)
        self.status_queue = Queue()
        self.original_hashes = {}
        self.original_files = {}
        self.chunk_size = chunk_size
        self.encryption_keys = {}

    def store_file(self, filename, data, retries=2, encrypt=False, password=None):
        attempt = 0
        while attempt <= retries:
            active_nodes = [node for node in self.nodes if node.active]
            if len(active_nodes) < self.replication_factor:
                self.status_queue.put(f"Error: Not enough active nodes ({len(active_nodes)}) for {filename}. Retrying...")
                attempt += 1
                time.sleep(1)
                continue
            
            original_data = data
            if encrypt and password:
                key = Fernet.generate_key()  # Simplified; should derive from password
                cipher = Fernet(key)
                data = cipher.encrypt(data)
                self.encryption_keys[filename] = key
                self.status_queue.put(f"[Encrypted] {filename}")

            chunks = [data[i:i + self.chunk_size] for i in range(0, len(data), self.chunk_size)]
            chunk_map = {}
            for i, chunk in enumerate(chunks):
                chunk_id = f"{filename}_chunk_{i}"
                checksum = hashlib.sha256(chunk).hexdigest()
                selected_nodes = random.sample(active_nodes, self.replication_factor)
                for node in selected_nodes:
                    node.store(chunk_id, chunk, checksum)
                chunk_map[chunk_id] = [node.node_id for node in selected_nodes]
            
            self.original_hashes[filename] = hashlib.sha256(data).hexdigest()
            self.original_files[filename] = original_data
            self.status_queue.put(f"Stored {filename} ({len(chunks)} chunks) on nodes: {chunk_map}")
            return True
        self.status_queue.put(f"Failed to store {filename} after {retries} retries")
        return False

    def retrieve_file(self, filename, decrypt=False, password=None):
        chunks = []
        chunk_id = 0
        while True:
            chunk_name = f"{filename}_chunk_{chunk_id}"
            chunk_data = None
            for node in self.nodes:
                data = node.retrieve(chunk_name)
                if data is not None:
                    chunks.append(data)
                    chunk_data = data
                    break
            if chunk_data is None:
                if chunk_id == 0:
                    self.status_queue.put(f"Error: No chunks of {filename} found")
                break
            chunk_id += 1
        
        if not chunks:
            self.status_queue.put(f"Error: {filename} retrieval failed - no data retrieved")
            return None
        
        full_data = b''.join(chunks)
        if decrypt and filename in self.encryption_keys:
            try:
                cipher = Fernet(self.encryption_keys[filename])
                full_data = cipher.decrypt(full_data)
                self.status_queue.put(f"[Decrypted] {filename}")
            except Exception as e:
                self.status_queue.put(f"Error: Decryption failed for {filename} - {str(e)}")
                return None
        self.status_queue.put(f"Retrieved {filename} ({len(chunks)} chunks)")
        return full_data

    def delete_file(self, filename):
        chunk_id = 0
        deleted = False
        while True:
            chunk_name = f"{filename}_chunk_{chunk_id}"
            found = False
            for node in self.nodes:
                if node.delete(chunk_name):
                    found = True
                    deleted = True
            if not found:
                break
            chunk_id += 1
        
        if deleted:
            if filename in self.original_hashes:
                del self.original_hashes[filename]
            if filename in self.original_files:
                del self.original_files[filename]
            if filename in self.encryption_keys:
                del self.encryption_keys[filename]
            self.status_queue.put(f"Deleted {filename} from all nodes")
            return True
        self.status_queue.put(f"Error: {filename} not found for deletion")
        return False

    def list_files(self):
        files = {}
        for node in self.nodes:
            for chunk_name in node.storage:
                filename = chunk_name.split('_chunk_')[0]
                if filename not in files:
                    files[filename] = set()
                files[filename].add(node.node_id)
        return files

    def simulate_node_failure(self, node_id):
        if 0 <= node_id < len(self.nodes):
            self.nodes[node_id].fail()
            self.status_queue.put(f"Node {node_id} failed")
            return True
        return False

    def recover_node(self, node_id):
        if 0 <= node_id < len(self.nodes):
            self.nodes[node_id].recover()
            self.status_queue.put(f"Node {node_id} recovered")
            return True
        return False

# Node Process
def node_process(node_id, active_status, queue):
    while True:
        if not active_status.value:
            queue.put(f"Node {node_id} is down")
        time.sleep(2)

# GUI Application
class DFSGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Distributed File System")
        self.root.geometry("1000x800")
        self.root.configure(bg="#1E1E1E")

        # Style configuration (removed Progressbar style)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Helvetica", 10, "bold"), padding=5, background="#3E3E3E", foreground="white")
        style.map("TButton", background=[("active", "#5E5E5E")], foreground=[("active", "white")])
        style.configure("TLabel", background="#1E1E1E", foreground="#D4D4D4", font=("Helvetica", 12))

        self.dfs = DFS(num_nodes=3, replication_factor=2, chunk_size=1024)
        self.active_status = [Value('b', 1) for _ in range(len(self.dfs.nodes))]
        self.processes = []
        for i in range(len(self.dfs.nodes)):
            p = Process(target=node_process, args=(i, self.active_status[i], self.dfs.status_queue), daemon=True)
            self.processes.append(p)
            p.start()

        # Theme Setup
        self.themes = {"Dark": {"bg": "#1E1E1E", "fg": "#D4D4D4", "accent": "#00D4FF"},
                       "Light": {"bg": "#F0F0F0", "fg": "#333333", "accent": "#FF6F61"}}
        self.current_theme = "Dark"
        self.theme_var = tk.StringVar(value="Dark")

        # Header Frame
        self.header_frame = tk.Frame(root, bg="#2E2E2E", relief="raised", bd=2)
        self.header_frame.pack(fill="x", pady=(0, 10))
        tk.Label(self.header_frame, text="Distributed File System", font=("Helvetica", 18, "bold"), fg="#00D4FF", bg="#2E2E2E").pack(pady=10)
        ttk.OptionMenu(self.header_frame, self.theme_var, "Dark", *self.themes.keys(), command=self.switch_theme).pack(side="right", padx=10)

        # Upload Frame (removed progress bar)
        self.upload_frame = tk.Frame(root, bg="#252525", relief="groove", bd=2)
        self.upload_frame.pack(pady=10, padx=10, fill="x")
        tk.Label(self.upload_frame, text="Upload File", font=("Helvetica", 14, "bold"), fg="#FF6F61", bg="#252525").pack(pady=5)
        upload_inner = tk.Frame(self.upload_frame, bg="#252525")
        upload_inner.pack(pady=5)
        ttk.Button(upload_inner, text="Upload", command=self.upload_file).grid(row=0, column=0, padx=5)
        self.encrypt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(upload_inner, text="Encrypt", variable=self.encrypt_var).grid(row=0, column=1, padx=5)

        # Node Control Frame
        self.node_frame = tk.Frame(root, bg="#252525", relief="groove", bd=2)
        self.node_frame.pack(pady=10, padx=10, fill="x")
        tk.Label(self.node_frame, text="Node Status", font=("Helvetica", 14, "bold"), fg="#FF6F61", bg="#252525").pack(pady=5)
        node_inner_frame = tk.Frame(self.node_frame, bg="#252525")
        node_inner_frame.pack(pady=5)
        self.node_status_labels = []
        for i in range(len(self.dfs.nodes)):
            label = tk.Label(node_inner_frame, text=f"Node {i}: Active", fg="#00FF00", bg="#252525", font=("Helvetica", 11))
            label.grid(row=0, column=i, padx=15, pady=5)
            self.node_status_labels.append(label)
            btn_fail = ttk.Button(node_inner_frame, text="Fail", command=lambda x=i: self.fail_node(x))
            btn_recover = ttk.Button(node_inner_frame, text="Recover", command=lambda x=i: self.recover_node(x))
            btn_fail.grid(row=1, column=i, padx=5, pady=2)
            btn_recover.grid(row=2, column=i, padx=5, pady=2)
        self.auto_recover = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.node_frame, text="Auto-Recover", variable=self.auto_recover, command=self.toggle_auto_recovery).pack(pady=5)
        self.dashboard = tk.Canvas(self.node_frame, bg="#252525", height=100, highlightthickness=0)
        self.dashboard.pack(pady=5, fill="x")

        # File Operations Frame
        self.file_frame = tk.Frame(root, bg="#252525", relief="groove", bd=2)
        self.file_frame.pack(pady=10, padx=10, fill="x")
        tk.Label(self.file_frame, text="File Operations", font=("Helvetica", 14, "bold"), fg="#FF6F61", bg="#252525").pack(pady=5)
        file_inner_frame = tk.Frame(self.file_frame, bg="#252525")
        file_inner_frame.pack(pady=5)
        tk.Label(file_inner_frame, text="File Name:", font=("Helvetica", 11), fg="#D4D4D4", bg="#252525").grid(row=0, column=0, padx=5, pady=5)
        self.file_entry = tk.Entry(file_inner_frame, width=30, font=("Helvetica", 11), bg="#3E3E3E", fg="white", insertbackground="white")
        self.file_entry.grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(file_inner_frame, text="Retrieve", command=self.retrieve_file).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(file_inner_frame, text="Delete", command=self.delete_file).grid(row=0, column=3, padx=5, pady=5)
        ttk.Button(file_inner_frame, text="Compare", command=self.compare_file).grid(row=0, column=4, padx=5, pady=5)
        ttk.Button(file_inner_frame, text="Preview", command=self.preview_file).grid(row=0, column=5, padx=5, pady=5)
        self.file_list = ttk.Combobox(file_inner_frame, width=20, font=("Helvetica", 11))
        self.file_list.grid(row=0, column=6, padx=5, pady=5)

        # Status Frame
        self.status_frame = tk.Frame(root, bg="#252525", relief="sunken", bd=2)
        self.status_frame.pack(pady=10, padx=10, fill="both", expand=True)
        tk.Label(self.status_frame, text="Status Log", font=("Helvetica", 14, "bold"), fg="#FF6F61", bg="#252525").pack(pady=5)
        status_inner = tk.Frame(self.status_frame, bg="#252525")
        status_inner.pack(pady=5, fill="both", expand=True)
        self.status_text = tk.Text(status_inner, height=20, width=80, bg="#1E1E1E", fg="#D4D4D4", font=("Courier", 10), wrap="word", borderwidth=0)
        self.status_text.pack(side="left", pady=5, padx=5, fill="both", expand=True)
        scrollbar = ttk.Scrollbar(status_inner, orient="vertical", command=self.status_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.status_text.config(yscrollcommand=scrollbar.set)
        ttk.Button(self.status_frame, text="Save Log", command=self.save_log).pack(pady=5)

        # Initialize updates
        self.update_status()
        self.update_dashboard()
        self.update_file_list()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            filename = os.path.basename(file_path)
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                encrypt = self.encrypt_var.get()
                if self.dfs.store_file(filename, data, encrypt=encrypt):
                    self.status_text.insert(tk.END, f"[Uploaded] {filename} ({len(data)} bytes)\n")
                else:
                    messagebox.showerror("Error", "Failed to store file after retries")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")
                self.status_text.insert(tk.END, f"[Error] Upload failed: {str(e)}\n")

    def retrieve_file(self):
        filename = self.file_entry.get().strip()
        if not filename:
            messagebox.showwarning("Warning", "Enter a filename")
            return
        data = self.dfs.retrieve_file(filename, decrypt=self.encrypt_var.get())
        if data is not None:
            try:
                retrieved_path = os.path.join(os.getcwd(), f"retrieved_{filename}")
                with open(retrieved_path, 'wb') as f:
                    f.write(data)
                retrieved_hash = hashlib.sha256(data).hexdigest()
                original_hash = self.dfs.original_hashes.get(filename, "Unknown")
                integrity_status = "OK" if retrieved_hash == original_hash else "FAILED"
                self.status_text.insert(tk.END, f"[Retrieved] {filename} -> {retrieved_path}\n")
                self.status_text.insert(tk.END, f"[Integrity] {integrity_status} (Orig: {original_hash[:8]}..., Retr: {retrieved_hash[:8]}...)\n")

                if filename in self.dfs.original_files:
                    temp_original_path = os.path.join(os.getcwd(), f"temp_original_{filename}")
                    with open(temp_original_path, 'wb') as f:
                        f.write(self.dfs.original_files[filename])
                    result = compare_files(temp_original_path, retrieved_path, verbose=False)
                    if not result["identical"]:
                        self.status_text.insert(tk.END, "[Differences] (up to 5):\n")
                        for line_num, orig, retrieved in result["differences"]:
                            self.status_text.insert(tk.END, f"  Line {line_num}: Orig='{orig}', Retr='{retrieved}'\n")
                        if result["total_differences"] > 5:
                            self.status_text.insert(tk.END, f"  ...and {result['total_differences'] - 5} more.\n")
                        self.status_text.insert(tk.END, "---\n")
                    else:
                        self.status_text.insert(tk.END, "[Comparison] Files are identical.\n")
                    os.remove(temp_original_path)
                else:
                    self.status_text.insert(tk.END, "[Comparison] Original data unavailable.\n")

            except Exception as e:
                self.status_text.insert(tk.END, f"[Error] Failed to save {filename}: {str(e)}\n")
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")
        else:
            messagebox.showerror("Error", f"File '{filename}' not found or inaccessible")

    def delete_file(self):
        filename = self.file_entry.get().strip()
        if not filename:
            messagebox.showwarning("Warning", "Enter a filename to delete")
            return
        if self.dfs.delete_file(filename):
            self.status_text.insert(tk.END, f"[Deleted] {filename}\n")
        else:
            messagebox.showerror("Error", f"File '{filename}' not found for deletion")

    def compare_file(self):
        filename = self.file_entry.get().strip()
        if not filename:
            messagebox.showwarning("Warning", "Enter a filename to compare")
            return
        retrieved_path = os.path.join(os.getcwd(), f"retrieved_{filename}")
        if filename in self.dfs.original_files and os.path.exists(retrieved_path):
            temp_original_path = os.path.join(os.getcwd(), f"temp_original_{filename}")
            try:
                with open(temp_original_path, 'wb') as f:
                    f.write(self.dfs.original_files[filename])
                result = compare_files(temp_original_path, retrieved_path, verbose=False)
                if not result["identical"]:
                    self.status_text.insert(tk.END, f"[Comparing] {filename} vs retrieved_{filename} (up to 5):\n")
                    for line_num, orig, retrieved in result["differences"]:
                        self.status_text.insert(tk.END, f"  Line {line_num}: Orig='{orig}', Retr='{retrieved}'\n")
                    if result["total_differences"] > 5:
                        self.status_text.insert(tk.END, f"  ...and {result['total_differences'] - 5} more.\n")
                    self.status_text.insert(tk.END, "---\n")
                else:
                    self.status_text.insert(tk.END, f"[Comparison] Files are identical.\n")
            finally:
                if os.path.exists(temp_original_path):
                    os.remove(temp_original_path)
        else:
            messagebox.showerror("Error", f"Cannot compare: Original or retrieved file for '{filename}' not available")

    def preview_file(self):
        filename = self.file_entry.get().strip()
        if not filename:
            messagebox.showwarning("Warning", "Enter a filename to preview")
            return
        if filename in self.dfs.original_files:
            data = self.dfs.original_files[filename]
            preview_window = tk.Toplevel(self.root, bg=self.themes[self.current_theme]["bg"])
            preview_window.title(f"Preview: {filename}")
            preview_window.geometry("400x300")
            text = tk.Text(preview_window, bg="#252525", fg="#D4D4D4", font=("Consolas", 10), wrap="word")
            text.pack(padx=10, pady=10, fill="both", expand=True)
            try:
                text.insert(tk.END, data.decode('utf-8')[:1000])
            except UnicodeDecodeError:
                text.insert(tk.END, "Binary Data (Hex Preview):\n" + data[:100].hex())
            text.config(state="disabled")
        else:
            messagebox.showwarning("Warning", "File not found for preview")

    def list_files(self):
        files = self.dfs.list_files()
        if files:
            self.status_text.insert(tk.END, "[Stored Files]:\n")
            for filename, nodes in files.items():
                self.status_text.insert(tk.END, f"  {filename} on nodes {list(nodes)}\n")
        else:
            self.status_text.insert(tk.END, "[Status] No files stored.\n")

    def fail_node(self, node_id):
        self.dfs.simulate_node_failure(node_id)
        self.active_status[node_id].value = 0
        self.node_status_labels[node_id].config(text=f"Node {node_id}: Failed", fg="#FF4444")

    def recover_node(self, node_id):
        self.dfs.recover_node(node_id)
        self.active_status[node_id].value = 1
        self.node_status_labels[node_id].config(text=f"Node {node_id}: Active", fg="#00FF00")

    def update_status(self):
        while not self.dfs.status_queue.empty():
            try:
                message = self.dfs.status_queue.get_nowait()
                self.status_text.insert(tk.END, f"[Log] {message}\n")
                self.status_text.see(tk.END)
            except Queue.Empty:
                break
        self.root.after(1000, self.update_status)

    def update_dashboard(self):
        self.dashboard.delete("all")
        for i, node in enumerate(self.dfs.nodes):
            color = "#00FF00" if node.active else "#FF4444"
            self.dashboard.create_rectangle(20 + i*100, 20, 80 + i*100, 80, fill=color, outline="")
            self.dashboard.create_text(50 + i*100, 90, text=f"Node {i}", fill="#D4D4D4", font=("Helvetica", 10))
            self.dashboard.create_text(50 + i*100, 10, text=f"Chunks: {len(node.storage)}", fill="#D4D4D4", font=("Helvetica", 8))
        self.root.after(1000, self.update_dashboard)

    def update_file_list(self):
        files = list(self.dfs.list_files().keys())
        self.file_list["values"] = files
        if files and not self.file_list.get():
            self.file_list.set(files[0])
        self.root.after(5000, self.update_file_list)

    def toggle_auto_recovery(self):
        if self.auto_recover.get():
            self.check_and_recover()

    def check_and_recover(self):
        if self.auto_recover.get():
            for i, node in enumerate(self.dfs.nodes):
                if not node.active and random.random() > 0.7:
                    self.recover_node(i)
            self.root.after(5000, self.check_and_recover)

    def switch_theme(self, theme):
        self.current_theme = theme
        colors = self.themes[theme]
        self.root.configure(bg=colors["bg"])
        self.header_frame.configure(bg="#2E2E2E" if theme == "Dark" else "#D0D0D0")
        self.upload_frame.configure(bg=colors["bg"])
        self.node_frame.configure(bg=colors["bg"])
        self.file_frame.configure(bg=colors["bg"])
        self.status_frame.configure(bg=colors["bg"])
        for widget in self.root.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    child.configure(bg=colors["bg"], fg=colors["fg"])
                elif isinstance(child, tk.Text):
                    child.configure(bg="#1E1E1E" if theme == "Dark" else "#FFFFFF", fg=colors["fg"])
                elif isinstance(child, tk.Entry):
                    child.configure(bg="#3E3E3E" if theme == "Dark" else "#FFFFFF", fg=colors["fg"])
        self.dashboard.configure(bg=colors["bg"])

    def save_log(self):
        try:
            log_content = self.status_text.get("1.0", tk.END)
            with open("dfs_log.txt", "w") as f:
                f.write(f"Log saved at {time.ctime()}\n\n{log_content}")
            popup = tk.Toplevel(self.root, bg=self.themes[self.current_theme]["bg"])
            popup.geometry("200x100")
            tk.Label(popup, text="Log Saved!", font=("Helvetica", 12, "bold"), fg="#00FF00", bg=self.themes[self.current_theme]["bg"]).pack(pady=10)
            popup.after(2000, popup.destroy)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save log: {str(e)}")

    def on_closing(self):
        for p in self.processes:
            p.terminate()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = DFSGUI(root)
    root.mainloop()
