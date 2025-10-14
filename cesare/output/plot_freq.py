# plot_freq.py
# Legge i file CSV di distribuzione lettere (source e cipher)
# e crea due grafici PNG pronti per essere inseriti nella pagina HTML.

import pandas as pd
import matplotlib.pyplot as plt

def plot_distribution(csv_path, title, output_path):
    """Crea e salva un grafico di distribuzione lettere."""
    # Legge il CSV
    df = pd.read_csv(csv_path)
    
    # Rimuove eventuale riga 'TOTAL'
    df = df[df["Letter"] != "TOTAL"]

    # Disegna il grafico
    plt.figure(figsize=(10, 5))
    plt.bar(df["Letter"], df["Percent"], edgecolor='black')
    plt.title(title, fontsize=14)
    plt.xlabel("Lettera")
    plt.ylabel("Frequenza (%)")
    plt.xticks(rotation=0)
    plt.tight_layout()
    
    # Salva come PNG
    plt.savefig(output_path, dpi=200)
    plt.close()
    print(f"✓ Salvato {output_path}")

# Percorsi dei file
plot_distribution("source_freq.csv", "Distribuzione lettere – Testo originale", "source_freq.png")
plot_distribution("cipher_freq.csv", "Distribuzione lettere – Testo cifrato", "cipher_freq.png")
