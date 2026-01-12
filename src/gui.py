import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import crypto_utils
from tkinter.font import Font
import pyperclip

# --- COLORS & THEME ---
BG_COLOR = "#F1F5F9"       # Light gray-blue background
CARD_COLOR = "#FFFFFF"     # Pure white cards
ACCENT_COLOR = "#2563EB"   # Modern vibrant blue
TEXT_COLOR = "#1E293B"     # Deep slate text
SUBTEXT_COLOR = "#64748B"  # Muted slate gray
ERROR_COLOR = "#DC2626"    # Visible red
SUCCESS_COLOR = "#16A34A"  # Visible green

class HashXApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HASHX - Secure Crypto Suite")
        self.geometry("900x700")
        self.configure(bg=BG_COLOR)
        
        # Configure Styles
        self.setup_styles()
        
        # Main Layout
        self.main_container = tk.Frame(self, bg=BG_COLOR)
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        self.create_header()
        
        # Tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill="both", expand=True, pady=(20, 0))
        
        self.hash_tab = HashTab(self.notebook)
        self.encrypt_tab = EncryptTab(self.notebook)
        self.asym_tab = AsymmetricTab(self.notebook)
        self.file_tab = FileToolsTab(self.notebook)
        self.utils_tab = UtilsTab(self.notebook)
        
        self.notebook.add(self.hash_tab, text="  Hashing  ")
        self.notebook.add(self.encrypt_tab, text="  Symmetric Encrypt  ")
        self.notebook.add(self.asym_tab, text="  Asymmetric (RSA)  ")
        self.notebook.add(self.file_tab, text="  File Tools  ")
        self.notebook.add(self.utils_tab, text="  Utilities  ")
        
        # Right Click Menu Setup
        self.context_menu = tk.Menu(self, tearoff=0, bg=CARD_COLOR, fg=TEXT_COLOR, activebackground=ACCENT_COLOR, activeforeground="white")
        self.context_menu.add_command(label="Cut", command=lambda: self.focus_get().event_generate("<<Cut>>"))
        self.context_menu.add_command(label="Copy", command=lambda: self.focus_get().event_generate("<<Copy>>"))
        self.context_menu.add_command(label="Paste", command=lambda: self.focus_get().event_generate("<<Paste>>"))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=self.select_all)
        
        # Global Bindings for Right Click
        self.bind_class("Text", "<Button-3>", self.show_context_menu)
        self.bind_class("Entry", "<Button-3>", self.show_context_menu)
        self.bind_class("TEntry", "<Button-3>", self.show_context_menu)

    def select_all(self, event=None):
        widget = self.focus_get()
        if isinstance(widget, tk.Text):
            widget.tag_add("sel", "1.0", "end")
        elif isinstance(widget, (tk.Entry, ttk.Entry)):
            widget.select_range(0, "end")
            widget.icursor("end")
        return "break"

    def show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Fonts
        default_font = ("Segoe UI", 10)
        header_font = ("Segoe UI", 12, "bold")
        
        # Notebook (Tabs)
        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", 
                        background=BG_COLOR, 
                        foreground=SUBTEXT_COLOR, 
                        font=header_font, 
                        padding=[15, 8],
                        borderwidth=0)
        style.map("TNotebook.Tab", 
                  background=[("selected", CARD_COLOR), ("active", "#E2E8F0")],
                  foreground=[("selected", ACCENT_COLOR)])
        
        # Frames
        style.configure("Card.TFrame", background=CARD_COLOR, relief="flat")
        
        # Labels
        style.configure("TLabel", background=CARD_COLOR, foreground=TEXT_COLOR, font=default_font)
        style.configure("Title.TLabel", background=BG_COLOR, foreground=ACCENT_COLOR, font=("Segoe UI", 24, "bold"))
        style.configure("Header.TLabel", background=CARD_COLOR, foreground=ACCENT_COLOR, font=("Segoe UI", 14, "bold"))
        style.configure("Sub.TLabel", background=CARD_COLOR, foreground=SUBTEXT_COLOR, font=("Segoe UI", 9))
        
        # Buttons
        style.configure("TButton", 
                        background=ACCENT_COLOR, 
                        foreground="#FFFFFF", 
                        font=("Segoe UI", 10, "bold"), 
                        borderwidth=0, 
                        focuscolor=ACCENT_COLOR)
        style.map("TButton", 
                  background=[('active', '#1D4ED8'), ('pressed', '#1E40AF')])
        
        style.configure("Outline.TButton",
                        background=CARD_COLOR,
                        foreground=ACCENT_COLOR,
                        borderwidth=1,
                        relief="solid") # Note: 'clam' theme handles borders differently, might need adjustments
        
        # Entry
        style.configure("TEntry", 
                        fieldbackground="#F8FAFC", 
                        foreground=TEXT_COLOR, 
                        insertcolor=TEXT_COLOR,
                        borderwidth=1,
                        padding=5)
        
        # Radiobutton
        style.configure("TRadiobutton", background=CARD_COLOR, foreground=TEXT_COLOR, font=default_font)
        style.map("TRadiobutton", background=[('active', CARD_COLOR)])

    def create_header(self):
        header_frame = tk.Frame(self.main_container, bg=BG_COLOR)
        header_frame.pack(fill="x")
        
        title = ttk.Label(header_frame, text="HASHX", style="Title.TLabel")
        title.pack(side="left")
        
        subtitle = tk.Label(header_frame, text="Advanced Encryption Standard", bg=BG_COLOR, fg=SUBTEXT_COLOR, font=("Segoe UI", 10))
        subtitle.pack(side="left", padx=15, pady=(10, 0))
        
        # Utility Bar
        utl_frame = tk.Frame(header_frame, bg=BG_COLOR)
        utl_frame.pack(side="right", pady=(10, 0))
        
        ttk.Button(utl_frame, text="📋 Copy Result", width=15, style="Outline.TButton", command=self.quick_copy).pack(side="left", padx=5)
        ttk.Button(utl_frame, text="🗑️ Clear All", width=12, style="Outline.TButton", command=self.quick_clear).pack(side="left", padx=5)

    def quick_copy(self):
        # Find active tab and its result
        idx = self.notebook.index("current")
        tab = self.notebook.nametowidget(self.notebook.select())
        
        # Try to find common result variables or widgets
        try:
            if hasattr(tab, "output_var"):
                pyperclip.copy(tab.output_var.get())
                messagebox.showinfo("Copied", "Hash output copied to clipboard!")
            elif hasattr(tab, "res_text"):
                txt = tab.res_text.get("1.0", "end-1c")
                pyperclip.copy(txt)
                messagebox.showinfo("Copied", "Result copied to clipboard!")
            elif hasattr(tab, "res_output"):
                txt = tab.res_output.get("1.0", "end-1c")
                pyperclip.copy(txt)
                messagebox.showinfo("Copied", "Result copied to clipboard!")
        except:
            pass

    def quick_clear(self):
        # Find active tab and clear its inputs
        tab = self.notebook.nametowidget(self.notebook.select())
        for widget in tab.winfo_children():
            if isinstance(widget, tk.Text):
                widget.delete("1.0", "end")
            elif isinstance(widget, (tk.Entry, ttk.Entry)):
                widget.delete(0, "end")
        messagebox.showinfo("Cleared", "Current tab inputs have been cleared.")

class HashTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.pack(fill="both", expand=True)
        self.create_widgets()
        
    def create_widgets(self):
        # Grid layout
        self.columnconfigure(1, weight=1)
        
        # Input Section
        ttk.Label(self, text="Input Text", style="Header.TLabel").grid(row=0, column=0, sticky="w", padx=20, pady=(20, 5))
        self.input_text = tk.Text(self, height=5, bg="#F8FAFC", fg=TEXT_COLOR, font=("Consolas", 10), insertbackground=TEXT_COLOR, relief="solid", borderwidth=1, padx=10, pady=10)
        self.input_text.grid(row=1, column=0, columnspan=2, sticky="ew", padx=20, pady=(0, 20))
        
        # Options
        opts_frame = ttk.Frame(self, style="Card.TFrame")
        opts_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=20)
        
        ttk.Label(opts_frame, text="Algorithm:", style="TLabel").pack(side="left", padx=(0, 10))
        self.algo_var = tk.StringVar(value="sha256")
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            ttk.Radiobutton(opts_frame, text=algo.upper(), variable=self.algo_var, value=algo).pack(side="left", padx=10)
            
        ttk.Label(opts_frame, text="Salt (Optional):", style="TLabel").pack(side="left", padx=(20, 10))
        self.salt_entry = ttk.Entry(opts_frame, width=20)
        self.salt_entry.pack(side="left")
        
        # Action
        btn_frame = ttk.Frame(self, style="Card.TFrame")
        btn_frame.grid(row=3, column=0, columnspan=2, sticky="ew", padx=20, pady=20)
        ttk.Button(btn_frame, text="GENERATE HASH", command=self.generate).pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Output
        ttk.Label(self, text="Generated Hash", style="Header.TLabel").grid(row=4, column=0, sticky="w", padx=20, pady=(10, 5))
        self.output_var = tk.StringVar()
        self.output_entry = ttk.Entry(self, textvariable=self.output_var, font=("Consolas", 11), state="readonly")
        self.output_entry.grid(row=5, column=0, sticky="ew", padx=(20, 5))
        
        ttk.Button(self, text="COPY", width=8, command=self.copy_hash).grid(row=5, column=1, sticky="w", padx=(0, 20))
        
    def generate(self):
        data = self.input_text.get("1.0", "end-1c")
        algo = self.algo_var.get()
        salt = self.salt_entry.get()
        
        try:
            res = crypto_utils.generate_hash(data, algo, salt)
            self.output_var.set(res)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def copy_hash(self):
        pyperclip.copy(self.output_var.get())

class EncryptTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.key = None
        self.salt = None
        self.create_widgets()
        
    def create_widgets(self):
        # Container
        content = tk.Frame(self, bg=CARD_COLOR)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Password / Key Gen
        kp_frame = tk.LabelFrame(content, text="Key Generation", bg=CARD_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10, "bold"))
        kp_frame.pack(fill="x", pady=(0, 20), ipadx=10, ipady=10)
        
        ttk.Label(kp_frame, text="Password:", style="TLabel").pack(side="left", padx=10)
        self.pass_entry = ttk.Entry(kp_frame, show="•", width=30)
        self.pass_entry.pack(side="left", padx=5)
        
        ttk.Button(kp_frame, text="SET KEY", command=self.derive_key).pack(side="left", padx=10)
        self.status_lbl = ttk.Label(kp_frame, text="Key: Not Set", foreground=ERROR_COLOR)
        self.status_lbl.pack(side="left", padx=10)
        
        # Input
        ttk.Label(content, text="Message", style="Header.TLabel").pack(anchor="w")
        self.msg_text = tk.Text(content, height=8, bg="#F8FAFC", fg=TEXT_COLOR, font=("Consolas", 10), insertbackground=TEXT_COLOR, relief="solid", borderwidth=1, padx=10, pady=10)
        self.msg_text.pack(fill="x", pady=(5, 20))
        
        # Buttons
        act_frame = ttk.Frame(content, style="Card.TFrame")
        act_frame.pack(fill="x", pady=10)
        
        ttk.Button(act_frame, text="ENCRYPT", command=self.encrypt).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ttk.Button(act_frame, text="DECRYPT", command=self.decrypt).pack(side="left", expand=True, fill="x", padx=(5, 0))
        
        # Output
        ttk.Label(content, text="Result", style="Header.TLabel").pack(anchor="w")
        self.res_text = tk.Text(content, height=8, bg="#F1F5F9", fg=ACCENT_COLOR, font=("Consolas", 10), state="disabled", relief="flat", padx=10, pady=10)
        self.res_text.pack(fill="x", pady=(5, 10))

        ttk.Button(content, text="COPY RESULT", command=self.copy_result).pack(anchor="e")
        
    def derive_key(self):
        pwd = self.pass_entry.get()
        if not pwd:
            messagebox.showwarning("Input", "Please enter a password.")
            return
        
        self.key, self.salt = crypto_utils.generate_key_from_password(pwd)
        self.status_lbl.config(text="Key: Active", foreground=SUCCESS_COLOR)
        
    def encrypt(self):
        if not self.key:
            messagebox.showerror("Error", "Set a key first!")
            return
        
        msg = self.msg_text.get("1.0", "end-1c")
        try:
            res = crypto_utils.encrypt_message(msg, self.key)
            self.show_result(res)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption Failed: {e}")
            
    def decrypt(self):
        if not self.key:
            messagebox.showerror("Error", "Set a key first!")
            return
            
        msg = self.msg_text.get("1.0", "end-1c")
        try:
            res = crypto_utils.decrypt_message(msg, self.key)
            self.show_result(res)
        except Exception as e:
            messagebox.showerror("Error", "Decryption Failed. Wrong key or corrupted data.")
            
    def show_result(self, text):
        self.res_text.config(state="normal")
        self.res_text.delete("1.0", "end")
        self.res_text.insert("1.0", text)
        self.res_text.config(state="disabled")
        
    def copy_result(self):
        pyperclip.copy(self.res_text.get("1.0", "end-1c"))

class AsymmetricTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.priv_key = None
        self.pub_key = None
        self.create_widgets()
        
    def create_widgets(self):
        content = tk.Frame(self, bg=CARD_COLOR)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Key Gen
        ttk.Button(content, text="GENERATE NEW RSA KEYPAIR", command=self.gen_keys).pack(fill="x", pady=(0, 10))
        
        # Keys Display
        keys_pane = tk.PanedWindow(content, orient="horizontal", bg=CARD_COLOR, sashwidth=4)
        keys_pane.pack(fill="both", expand=True, pady=10)
        
        f1 = tk.Frame(keys_pane, bg=CARD_COLOR)
        ttk.Label(f1, text="Public Key (Share this)", style="Sub.TLabel").pack(anchor="w")
        self.pub_text = tk.Text(f1, height=6, bg="#F8FAFC", fg="#16A34A", font=("Consolas", 8), insertbackground=TEXT_COLOR, relief="solid", borderwidth=1)
        self.pub_text.pack(fill="both", expand=True)
        keys_pane.add(f1)
        
        f2 = tk.Frame(keys_pane, bg=CARD_COLOR)
        ttk.Label(f2, text="Private Key (Keep safe)", style="Sub.TLabel").pack(anchor="w")
        self.priv_text = tk.Text(f2, height=6, bg="#F8FAFC", fg="#D946EF", font=("Consolas", 8), insertbackground=TEXT_COLOR, relief="solid", borderwidth=1)
        self.priv_text.pack(fill="both", expand=True)
        keys_pane.add(f2)
        
        # Msg
        ttk.Label(content, text="Data to Process", style="Header.TLabel").pack(anchor="w", pady=(10, 0))
        self.msg_input = tk.Text(content, height=4, bg="#F8FAFC", fg=TEXT_COLOR, font=("Consolas", 10), insertbackground=TEXT_COLOR, relief="solid", borderwidth=1)
        self.msg_input.pack(fill="x", pady=5)
        
        act_frame = ttk.Frame(content, style="Card.TFrame")
        act_frame.pack(fill="x", pady=10)
        
        b_row1 = tk.Frame(act_frame, bg=CARD_COLOR)
        b_row1.pack(fill="x")
        ttk.Button(b_row1, text="ENCRYPT (Use Pub Key)", command=self.do_encrypt).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ttk.Button(b_row1, text="DECRYPT (Use Priv Key)", command=self.do_decrypt).pack(side="left", expand=True, fill="x", padx=(5, 0))
        
        b_row2 = tk.Frame(act_frame, bg=CARD_COLOR)
        b_row2.pack(fill="x", pady=(5, 0))
        ttk.Button(b_row2, text="SIGN (Use Priv Key)", command=self.do_sign).pack(side="left", expand=True, fill="x", padx=(0, 5))
        ttk.Button(b_row2, text="VERIFY (Use Pub Key)", command=self.do_verify).pack(side="left", expand=True, fill="x", padx=(5, 0))
        
        # Result
        self.res_output = tk.Text(content, height=4, bg="#F1F5F9", fg=ACCENT_COLOR, font=("Consolas", 10), state="disabled", relief="solid", borderwidth=1)
        self.res_output.pack(fill="x")
        
    def gen_keys(self):
        try:
            self.priv_key, self.pub_key = crypto_utils.generate_rsa_keypair()
            
            self.priv_text.delete("1.0", "end")
            self.priv_text.insert("1.0", self.priv_key)
            
            self.pub_text.delete("1.0", "end")
            self.pub_text.insert("1.0", self.pub_key)
            
            messagebox.showinfo("Success", "New RSA Keypair Generated!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def do_encrypt(self):
        msg = self.msg_input.get("1.0", "end-1c")
        # In a real app, user might paste a public key. For now use the one in the box.
        pub_pem = self.pub_text.get("1.0", "end-1c")
        if not pub_pem.strip():
            messagebox.showerror("Error", "No Public Key found.")
            return
            
        try:
            enc = crypto_utils.rsa_encrypt(msg, pub_pem)
            self.show_res(enc)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            
    def do_decrypt(self):
        msg = self.msg_input.get("1.0", "end-1c")
        priv_pem = self.priv_text.get("1.0", "end-1c")
        if not priv_pem.strip():
            messagebox.showerror("Error", "No Private Key found.")
            return
            
        try:
            dec = crypto_utils.rsa_decrypt(msg, priv_pem)
            self.show_res(dec)
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed.")

    def do_sign(self):
        msg = self.msg_input.get("1.0", "end-1c")
        priv_pem = self.priv_text.get("1.0", "end-1c")
        if not priv_pem.strip():
            messagebox.showerror("Error", "No Private Key found.")
            return
        try:
            sig = crypto_utils.rsa_sign(msg, priv_pem)
            self.show_res(sig)
        except Exception as e:
            messagebox.showerror("Error", f"Signing failed: {e}")

    def do_verify(self):
        # Verification needs: Message, Signature (e.g. pasted into result box or elsewhere), and Public key
        # For simplicity, we assume result box might contain common input/output area
        msg = self.msg_input.get("1.0", "end-1c")
        pub_pem = self.pub_text.get("1.0", "end-1c")
        signature = self.res_output.get("1.0", "end-1c").strip()
        
        if not signature:
            messagebox.showwarning("Input", "Paste the signature into the Result/Output box to verify.")
            return

        if not pub_pem.strip():
            messagebox.showerror("Error", "No Public Key found.")
            return

        try:
            is_valid = crypto_utils.rsa_verify(msg, signature, pub_pem)
            if is_valid:
                messagebox.showinfo("Verification", "✅ Signature is VALID!")
            else:
                messagebox.showerror("Verification", "❌ Signature is INVALID!")
        except Exception as e:
            messagebox.showerror("Error", f"Verification error: {e}")

    def show_res(self, text):
        self.res_output.config(state="normal")
        self.res_output.delete("1.0", "end")
        self.res_output.insert("1.0", text)
        self.res_output.config(state="disabled")

class FileToolsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.key = None
        self.create_widgets()
        
    def create_widgets(self):
        content = tk.Frame(self, bg=CARD_COLOR)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Key Section for Files
        k_frame = tk.LabelFrame(content, text="Symmetric Key for Files", bg=CARD_COLOR, fg=TEXT_COLOR)
        k_frame.pack(fill="x", pady=(0, 20), ipadx=10, ipady=10)
        
        ttk.Label(k_frame, text="Password:").pack(side="left", padx=5)
        self.file_pass = ttk.Entry(k_frame, show="•", width=20)
        self.file_pass.pack(side="left", padx=5)
        ttk.Button(k_frame, text="SET KEY", command=self.derive_file_key).pack(side="left", padx=5)
        self.key_status = ttk.Label(k_frame, text="Key: Not Set", foreground=ERROR_COLOR)
        self.key_status.pack(side="left", padx=10)

        # File Hashing
        h_frame = tk.LabelFrame(content, text="File Hashing", bg=CARD_COLOR, fg=TEXT_COLOR)
        h_frame.pack(fill="x", pady=10, ipadx=10, ipady=10)
        
        self.hash_file_path = tk.StringVar()
        ttk.Entry(h_frame, textvariable=self.hash_file_path, width=50).pack(side="left", padx=5)
        ttk.Button(h_frame, text="BROWSE", command=lambda: self.browse(self.hash_file_path)).pack(side="left", padx=5)
        ttk.Button(h_frame, text="HASH FILE", command=self.do_hash_file).pack(side="left", padx=5)

        # File Encryption
        e_frame = tk.LabelFrame(content, text="File Encryption / Decryption", bg=CARD_COLOR, fg=TEXT_COLOR)
        e_frame.pack(fill="x", pady=10, ipadx=10, ipady=10)
        
        self.target_file_path = tk.StringVar()
        ttk.Entry(e_frame, textvariable=self.target_file_path, width=50).pack(side="left", padx=5)
        ttk.Button(e_frame, text="BROWSE", command=lambda: self.browse(self.target_file_path)).pack(side="left", padx=5)
        
        btn_box = tk.Frame(e_frame, bg=CARD_COLOR)
        btn_box.pack(fill="x", pady=5)
        ttk.Button(btn_box, text="ENCRYPT FILE", command=self.do_encrypt_file).pack(side="left", padx=5)
        ttk.Button(btn_box, text="DECRYPT FILE", command=self.do_decrypt_file).pack(side="left", padx=5)

    def browse(self, var):
        path = filedialog.askopenfilename()
        if path:
            var.set(path)

    def derive_file_key(self):
        pwd = self.file_pass.get()
        if not pwd:
            messagebox.showwarning("Input", "Please enter a password.")
            return
        self.key, _ = crypto_utils.generate_key_from_password(pwd)
        self.key_status.config(text="Key: Active", foreground=SUCCESS_COLOR)

    def do_hash_file(self):
        path = self.hash_file_path.get()
        if not path: return
        try:
            h = crypto_utils.hash_file(path)
            messagebox.showinfo("File Hash (SHA256)", f"Hash:\n{h}")
            pyperclip.copy(h)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_encrypt_file(self):
        if not self.key: 
            messagebox.showerror("Error", "Set a key first!")
            return
        ipath = self.target_file_path.get()
        if not ipath: return
        opath = filedialog.asksaveasfilename(defaultextension=".enc")
        if not opath: return
        try:
            crypto_utils.encrypt_file(ipath, opath, self.key)
            messagebox.showinfo("Success", f"File encrypted to:\n{opath}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt_file(self):
        if not self.key: 
            messagebox.showerror("Error", "Set a key first!")
            return
        ipath = self.target_file_path.get()
        if not ipath: return
        opath = filedialog.asksaveasfilename()
        if not opath: return
        try:
            crypto_utils.decrypt_file(ipath, opath, self.key)
            messagebox.showinfo("Success", f"File decrypted to:\n{opath}")
        except Exception as e:
            messagebox.showerror("Error", "Decryption failed. Check key.")

class UtilsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, style="Card.TFrame")
        self.create_widgets()
        
    def create_widgets(self):
        content = tk.Frame(self, bg=CARD_COLOR)
        content.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Password Generator
        pw_frame = tk.LabelFrame(content, text="Strong Password Generator", bg=CARD_COLOR, fg=TEXT_COLOR)
        pw_frame.pack(fill="x", pady=(0, 20), ipadx=10, ipady=10)
        
        ttk.Label(pw_frame, text="Length:").pack(side="left", padx=5)
        self.pw_len = ttk.Spinbox(pw_frame, from_=8, to=128, width=5)
        self.pw_len.set(16)
        self.pw_len.pack(side="left", padx=5)
        
        self.sym_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(pw_frame, text="Includes Symbols", variable=self.sym_var).pack(side="left", padx=10)
        
        ttk.Button(pw_frame, text="GENERATE", command=self.gen_pw).pack(side="left", padx=5)
        
        self.pw_res = ttk.Entry(pw_frame, font=("Consolas", 10))
        self.pw_res.pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(pw_frame, text="COPY", width=5, command=lambda: pyperclip.copy(self.pw_res.get())).pack(side="left", padx=5)

        # Base64 Tools
        b64_frame = tk.LabelFrame(content, text="Base64 Encoder / Decoder", bg=CARD_COLOR, fg=TEXT_COLOR)
        b64_frame.pack(fill="both", expand=True, pady=10, ipadx=10, ipady=10)
        
        ttk.Label(b64_frame, text="Data").pack(anchor="w")
        self.b64_input = tk.Text(b64_frame, height=5, bg="#F8FAFC", fg=TEXT_COLOR, font=("Consolas", 10), insertbackground=TEXT_COLOR, relief="solid", borderwidth=1)
        self.b64_input.pack(fill="both", expand=True, pady=5)
        
        btn_box = tk.Frame(b64_frame, bg=CARD_COLOR)
        btn_box.pack(fill="x", pady=5)
        ttk.Button(btn_box, text="ENCODE TO B64", command=self.do_b64_enc).pack(side="left", expand=True, fill="x", padx=2)
        ttk.Button(btn_box, text="DECODE FROM B64", command=self.do_b64_dec).pack(side="left", expand=True, fill="x", padx=2)
        
        ttk.Label(b64_frame, text="Result").pack(anchor="w")
        self.b64_res = tk.Text(b64_frame, height=5, bg="#F1F5F9", fg=ACCENT_COLOR, font=("Consolas", 10), relief="solid", borderwidth=1)
        self.b64_res.pack(fill="both", expand=True, pady=5)
        

    def gen_pw(self):
        try:
            l = int(self.pw_len.get())
            s = self.sym_var.get()
            pw = crypto_utils.generate_strong_password(l, s)
            self.pw_res.delete(0, "end")
            self.pw_res.insert(0, pw)
        except: pass

    def do_b64_enc(self):
        data = self.b64_input.get("1.0", "end-1c")
        if not data: return
        try:
            res = crypto_utils.base64_encode_str(data)
            self.b64_res.delete("1.0", "end")
            self.b64_res.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_b64_dec(self):
        data = self.b64_input.get("1.0", "end-1c")
        if not data: return
        try:
            res = crypto_utils.base64_decode_str(data)
            self.b64_res.delete("1.0", "end")
            self.b64_res.insert("1.0", res)
        except Exception as e:
            messagebox.showerror("Error", "Invalid Base64 data.")

def main():
    app = HashXApp()
    app.mainloop()

if __name__ == "__main__":
    main()
