#!/usr/bin/env python3
"""
pwtool_gui.py
Password Strength Analyzer + Custom Wordlist Generator (GUI-only)

Save as pwtool_gui.py and run:
    python pwtool_gui.py

Optional dependencies:
    pip install zxcvbn-python nltk
    python -m nltk.downloader punkt

Ethics: Use only for authorized testing or recovery of your own accounts.
"""
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import itertools
import math
import os
import time
from datetime import datetime

# Optional libs (not required)
try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except Exception:
    HAS_ZXCVBN = False

try:
    import nltk
    from nltk.tokenize import word_tokenize
    HAS_NLTK = True
except Exception:
    HAS_NLTK = False

# ---------------- Configuration ----------------
COMMON_SUFFIXES = ['', '!', '123', '1234', '2020', '2021', '2022', '2023', '2024', '@', '#']
COMMON_SEPARATORS = ['', '.', '_', '-', '']
LEET_MAP = {
    'a': ['4', '@'],
    'b': ['8'],
    'e': ['3'],
    'i': ['1', '!'],
    'l': ['1', '|'],
    'o': ['0'],
    's': ['5', '$'],
    't': ['7'],
    'g': ['9'],
    'z': ['2']
}

MAX_PREVIEW_LINES = 500  # GUI preview cap

# ---------------- Utilities ----------------
def safe_tokenize(text):
    if not text:
        return []
    if HAS_NLTK:
        try:
            tokens = word_tokenize(text)
            return [t for t in tokens if any(c.isalnum() for c in t)]
        except Exception:
            pass
    # fallback split by commas/spaces
    parts = []
    for piece in text.replace(',', ' ').split():
        p = piece.strip()
        if p:
            parts.append(p)
    return parts

def unique_preserve_order(seq):
    seen = set()
    out = []
    for s in seq:
        if s not in seen:
            out.append(s)
            seen.add(s)
    return out

def leet_variants(token, max_variants=60):
    token = token.strip()
    if not token:
        return []
    variants = set([token])
    positions = [i for i, ch in enumerate(token.lower()) if ch in LEET_MAP]
    # single char replacements
    for i in positions:
        for rep in LEET_MAP[token[i].lower()]:
            v = token[:i] + rep + token[i+1:]
            variants.add(v)
            if len(variants) >= max_variants:
                return list(variants)
    # two-char replacements
    for i, j in itertools.combinations(positions, 2):
        for r1 in LEET_MAP[token[i].lower()]:
            for r2 in LEET_MAP[token[j].lower()]:
                v = token[:i] + r1 + token[i+1:j] + r2 + token[j+1:]
                variants.add(v)
                if len(variants) >= max_variants:
                    return list(variants)
    return list(variants)

def simple_entropy(password):
    if not password:
        return 0.0
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(not c.isalnum() for c in password):
        charset += 32
    if charset == 0:
        charset = 1
    return math.log2(charset) * len(password)

def analyze_password(password):
    if not password:
        return {"error": "No password provided."}
    if HAS_ZXCVBN:
        try:
            res = zxcvbn(password)
            out = {
                "score": res.get('score'),
                "guesses": res.get('guesses'),
                "crack_times_display": res.get('crack_times_display'),
                "feedback": res.get('feedback')
            }
            return out
        except Exception as e:
            # fall through to entropy
            pass
    ent = simple_entropy(password)
    if ent < 28:
        score = 0
    elif ent < 36:
        score = 1
    elif ent < 60:
        score = 2
    elif ent < 80:
        score = 3
    else:
        score = 4
    return {"score": score, "entropy_bits": round(ent, 2),
            "note": "zxcvbn not available; used simple entropy estimate."}

def parse_year_range(s):
    if not s:
        return None
    s = s.strip()
    if '-' in s:
        a, b = s.split('-', 1)
    elif ':' in s:
        a, b = s.split(':', 1)
    else:
        a = s
        b = None
    try:
        start = int(a)
    except:
        return None
    if b:
        try:
            end = int(b)
        except:
            end = datetime.now().year
    else:
        end = datetime.now().year
    if start > end:
        start, end = end, start
    return (max(1900, start), min(2100, end))

# ---------------- Wordlist generator ----------------
def generate_wordlist(bases, years_range=None, add_leet=True,
                      append_common_suffixes=True, combine_with_separators=True,
                      max_output=50000):
    seeds = []
    for b in bases:
        if not b:
            continue
        seeds.extend([b, b.lower(), b.title(), b.upper()])
    # include digit-only parts
    for s in list(seeds):
        digits = ''.join(ch for ch in s if ch.isdigit())
        if digits:
            seeds.append(digits)
    seeds = unique_preserve_order([s for s in seeds if s])

    variants = set()
    for s in seeds:
        variants.add(s)
        if add_leet:
            for lv in leet_variants(s):
                variants.add(lv)

    variants = list(variants)

    combos = set()
    max_combo_len = 3
    # build small permutations (capped)
    for r in range(1, max_combo_len + 1):
        for combo in itertools.permutations(variants, r):
            joined = ''.join(combo)
            combos.add(joined)
            if len(combos) >= max_output // 3:
                break
        if len(combos) >= max_output // 3:
            break

    sep_joined = set()
    if combine_with_separators:
        for r in range(1, 3):  # smaller set for separators
            for combo in itertools.permutations(variants, r):
                for sep in COMMON_SEPARATORS:
                    joined = sep.join(combo)
                    sep_joined.add(joined)
                if len(sep_joined) >= max_output // 3:
                    break
            if len(sep_joined) >= max_output // 3:
                break

    all_words = set()
    all_words.update(combos)
    all_words.update(sep_joined)
    all_words.update(variants)

    # append years
    if years_range:
        start, end = years_range
        to_add = set()
        for w in list(all_words):
            for y in range(start, end + 1):
                to_add.add(f"{w}{y}")
                to_add.add(f"{w}{str(y)[-2:]}")
        all_words.update(to_add)

    if append_common_suffixes:
        to_add = set()
        for w in list(all_words):
            for suf in COMMON_SUFFIXES:
                if suf:
                    to_add.add(w + suf)
        all_words.update(to_add)

    cleaned = [w for w in all_words if w and len(w) <= 64]
    cleaned = unique_preserve_order(sorted(cleaned, key=lambda x: (len(x), x)))
    if len(cleaned) > max_output:
        cleaned = cleaned[:max_output]
    return cleaned

def export_wordlist(words, path):
    with open(path, 'w', encoding='utf-8', errors='ignore') as f:
        for w in words:
            f.write(w + '\n')
    return os.path.abspath(path)

# ---------------- GUI ----------------
class PWToolGUI:
    def __init__(self, root):
        self.root = root
        root.title("Password Strength Analyzer & Wordlist Generator")
        root.geometry("820x640")
        root.resizable(True, True)

        # style
        style = ttk.Style()
        try:
            style.theme_use('vista')
        except:
            pass

        container = ttk.Frame(root, padding=12)
        container.pack(fill='both', expand=True)

        # Top: inputs
        inputs = ttk.LabelFrame(container, text="Inputs", padding=12)
        inputs.pack(fill='x', padx=4, pady=4)

        ttk.Label(inputs, text="Password (optional):").grid(row=0, column=0, sticky='w')
        self.pw_entry = ttk.Entry(inputs, width=50, show='*')
        self.pw_entry.grid(row=0, column=1, sticky='w', padx=4, pady=2)

        ttk.Label(inputs, text="Names / Words (comma separated):").grid(row=1, column=0, sticky='w')
        self.names_entry = ttk.Entry(inputs, width=70)
        self.names_entry.grid(row=1, column=1, sticky='w', padx=4, pady=2)

        ttk.Label(inputs, text="Pets / Favorites (comma separated):").grid(row=2, column=0, sticky='w')
        self.pets_entry = ttk.Entry(inputs, width=70)
        self.pets_entry.grid(row=2, column=1, sticky='w', padx=4, pady=2)

        ttk.Label(inputs, text="Dates / Numbers (comma separated):").grid(row=3, column=0, sticky='w')
        self.dates_entry = ttk.Entry(inputs, width=70)
        self.dates_entry.grid(row=3, column=1, sticky='w', padx=4, pady=2)

        ttk.Label(inputs, text="Years range (e.g. 1990-2025):").grid(row=4, column=0, sticky='w')
        self.years_entry = ttk.Entry(inputs, width=20)
        self.years_entry.grid(row=4, column=1, sticky='w', padx=4, pady=2)

        # options
        opts = ttk.LabelFrame(container, text="Options", padding=12)
        opts.pack(fill='x', padx=4, pady=4)

        self.leet_var = tk.IntVar(value=1)
        ttk.Checkbutton(opts, text="Include leetspeak variants", variable=self.leet_var).grid(row=0, column=0, sticky='w')
        self.suffix_var = tk.IntVar(value=1)
        ttk.Checkbutton(opts, text="Append common suffixes (123, !, years)", variable=self.suffix_var).grid(row=0, column=1, sticky='w')

        ttk.Label(opts, text="Max entries to generate:").grid(row=1, column=0, sticky='w', pady=(6,0))
        self.max_spin = tk.Spinbox(opts, from_=100, to=1000000, increment=100, width=12)
        self.max_spin.delete(0, 'end')
        self.max_spin.insert(0, "20000")
        self.max_spin.grid(row=1, column=1, sticky='w', pady=(6,0))

        # buttons
        btns = ttk.Frame(container)
        btns.pack(fill='x', padx=4, pady=6)
        ttk.Button(btns, text="Analyze Password", command=self.analyze_action).pack(side='left', padx=6)
        ttk.Button(btns, text="Generate Preview", command=self.gen_action).pack(side='left', padx=6)
        ttk.Button(btns, text="Generate & Save", command=self.save_action).pack(side='left', padx=6)
        ttk.Button(btns, text="Clear Preview", command=self.clear_preview).pack(side='left', padx=6)
        ttk.Button(btns, text="Quit", command=root.destroy).pack(side='right', padx=6)

        # progress & info
        info_frame = ttk.Frame(container)
        info_frame.pack(fill='x', padx=4, pady=4)
        self.progress = ttk.Progressbar(info_frame, mode='determinate')
        self.progress.pack(fill='x', padx=2, pady=2)
        self.status_label = ttk.Label(info_frame, text="Ready")
        self.status_label.pack(anchor='w', padx=4)

        # preview area
        preview = ttk.LabelFrame(container, text="Preview / Analysis", padding=8)
        preview.pack(fill='both', expand=True, padx=4, pady=4)
        self.text = tk.Text(preview, wrap='none')
        self.text.pack(fill='both', expand=True, side='left')
        # add scrollbars
        vsb = ttk.Scrollbar(preview, orient='vertical', command=self.text.yview)
        vsb.pack(side='right', fill='y')
        self.text.configure(yscrollcommand=vsb.set)

        # quick tip footer
        tip = ttk.Label(container, text="Tip: Use small max entries for quick previews. Use ethically.", foreground='gray')
        tip.pack(anchor='w', padx=6, pady=(4,0))

    def set_status(self, s):
        self.status_label.config(text=s)
        self.root.update_idletasks()

    def analyze_action(self):
        pw = self.pw_entry.get().strip()
        if not pw:
            messagebox.showinfo("Info", "Enter a password to analyze (optional for wordlist generation).")
            return
        self.set_status("Analyzing password...")
        self.progress.start(10)
        res = analyze_password(pw)
        self.progress.stop()
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, "Password Analysis Result\n")
        self.text.insert(tk.END, "------------------------\n")
        for k, v in res.items():
            self.text.insert(tk.END, f"{k}: {v}\n")
        self.set_status("Analysis complete.")

    def gen_action(self):
        seeds = []
        seeds.extend(safe_tokenize(self.names_entry.get()))
        seeds.extend(safe_tokenize(self.pets_entry.get()))
        seeds.extend(safe_tokenize(self.dates_entry.get()))
        pw = self.pw_entry.get().strip()
        if pw:
            seeds.append(pw)
        if not seeds:
            messagebox.showinfo("Info", "Please provide at least one seed (names/pets/dates/password).")
            return
        years_t = parse_year_range(self.years_entry.get().strip())
        try:
            maxv = int(self.max_spin.get())
        except:
            maxv = 20000
        self.set_status("Generating wordlist preview...")
        self.progress.start(6)
        words = generate_wordlist(
            bases=seeds,
            years_range=years_t,
            add_leet=bool(self.leet_var.get()),
            append_common_suffixes=bool(self.suffix_var.get()),
            combine_with_separators=True,
            max_output=maxv
        )
        self.progress.stop()
        self.text.delete('1.0', tk.END)
        self.text.insert(tk.END, f"Generated {len(words)} entries. Showing first {min(len(words), MAX_PREVIEW_LINES)} lines:\n\n")
        for i, w in enumerate(words[:MAX_PREVIEW_LINES], 1):
            self.text.insert(tk.END, f"{i}. {w}\n")
        if len(words) > MAX_PREVIEW_LINES:
            self.text.insert(tk.END, f"\n... (preview limited to {MAX_PREVIEW_LINES} lines)\n")
        self.set_status(f"Generated {len(words)} entries (preview).")

    def save_action(self):
        seeds = []
        seeds.extend(safe_tokenize(self.names_entry.get()))
        seeds.extend(safe_tokenize(self.pets_entry.get()))
        seeds.extend(safe_tokenize(self.dates_entry.get()))
        pw = self.pw_entry.get().strip()
        if pw:
            seeds.append(pw)
        if not seeds:
            messagebox.showinfo("Info", "Please provide at least one seed to generate and save a wordlist.")
            return
        years_t = parse_year_range(self.years_entry.get().strip())
        try:
            maxv = int(self.max_spin.get())
        except:
            maxv = 20000
        self.set_status("Generating full wordlist...")
        self.progress.start(6)
        words = generate_wordlist(
            bases=seeds,
            years_range=years_t,
            add_leet=bool(self.leet_var.get()),
            append_common_suffixes=bool(self.suffix_var.get()),
            combine_with_separators=True,
            max_output=maxv
        )
        self.progress.stop()
        # choose filename
        default = f"wordlist_{int(time.time())}.txt"
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default,
                                            filetypes=[("Text files", "*.txt")], title="Save wordlist as")
        if not path:
            self.set_status("Save cancelled.")
            return
        try:
            abs_path = export_wordlist(words, path)
            messagebox.showinfo("Saved", f"Wordlist saved to:\n{abs_path}")
            self.set_status(f"Saved to {abs_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save: {e}")
            self.set_status("Save failed.")

    def clear_preview(self):
        self.text.delete('1.0', tk.END)
        self.set_status("Preview cleared.")

def main():
    root = tk.Tk()
    app = PWToolGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
