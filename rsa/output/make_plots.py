#!/usr/bin/env python3
"""
plot_frequencies.py
Legge i CSV generati da rsa_freq.js e crea i grafici di distribuzione.

Uso:
    python3 plot_frequencies.py --indir rsa/output
"""

import pandas as pd
import matplotlib.pyplot as plt
import os
import argparse

def plot_csv(csv_path, title, out_path):
    df = pd.read_csv(csv_path)
    plt.figure(figsize=(9,4))
    plt.bar(df['letter'], df['freq'])
    plt.title(title, fontsize=13, fontweight='bold')
    plt.xlabel('Lettere (A–Z)')
    plt.ylabel('Frequenza')
    plt.grid(axis='y', linestyle='--', alpha=0.4)
    plt.tight_layout()
    plt.savefig(out_path, dpi=200)
    plt.close()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--indir', type=str, default='rsa/output',
                        help='Cartella contenente i file *.csv')
    args = parser.parse_args()

    indir = args.indir
    os.makedirs(indir, exist_ok=True)

    files = {
        'source_freq.csv': ('Distribuzione lettere (Plaintext)', 'source_freq.png'),
        'cipher_freq.csv': ('Distribuzione lettere (Ciphertext)', 'cipher_freq.png'),
        'guess_freq.csv':  ('Distribuzione lettere (Stima)', 'guess_freq.png'),
    }

    for csv_name, (title, out_name) in files.items():
        csv_path = os.path.join(indir, csv_name)
        out_path = os.path.join(indir, out_name)
        if os.path.exists(csv_path):
            print(f"[✓] Plot: {csv_name} → {out_name}")
            plot_csv(csv_path, title, out_path)
        else:
            print(f"[!] File non trovato: {csv_path}")

    print("\nTutti i grafici salvati in:", indir)

if __name__ == "__main__":
    main()
