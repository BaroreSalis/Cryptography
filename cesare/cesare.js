#!/usr/bin/env node
/**
 * cesare.js
 * - Legge un file di testo (UTF-8)
 * - Calcola distribuzione lettere (A–Z) del sorgente normalizzato
 * - Cifra con Cesare (shift scelto)
 * - Decifra il ciphertext via analisi di frequenza (chi^2 su frequenze italiane)
 * - Scrive risultati su file (CSV + TXT) e stampa un breve report Markdown
 *
 * Uso:
 *   node cesare.js --in input.txt --shift 7 --out output
 *
 * Parametri:
 *   --in    percorso file sorgente (obbligatorio)
 *   --shift intero 0..25 per cifratura (default 7)
 *   --out   directory di output (default "output")
 */

const fs = require('fs');
const path = require('path');

// ===================== Utils base =====================
function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--in') opts.input = args[++i];
    else if (args[i] === '--shift') opts.shift = parseInt(args[++i], 10);
    else if (args[i] === '--out') opts.outdir = args[++i];
  }
  if (!opts.input) {
    console.error('Errore: specifica --in <file>');
    process.exit(1);
  }
  if (isNaN(opts.shift)) opts.shift = 7;
  if (!opts.outdir) opts.outdir = 'output';
  return opts;
}

function ensureDir(d) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// Rimuove accenti/diacritici, tiene solo A-Z, uppercase
function normalizeText(text) {
  return text
    .toUpperCase()
    .normalize('NFD')
    .replace(/\p{Diacritic}/gu, '')
    .replace(/[^A-Z]/g, '');
}

function freqCount(t) {
  const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const counts = {};
  for (const L of letters) counts[L] = 0;
  for (const ch of t) if (counts[ch] !== undefined) counts[ch]++;
  const n = t.length || 1;
  const perc = {};
  for (const L of letters) perc[L] = (counts[L] * 100) / n;
  return { counts, perc, n };
}

function caesarShift(t, k) {
  const A = 'A'.charCodeAt(0);
  return t.replace(/[A-Z]/g, ch =>
    String.fromCharCode(((ch.charCodeAt(0) - A + k) % 26) + A)
  );
}

// Frequenze attese lettere italiane (somma ≈ 100)
const ITALIAN_FREQ = {
  A:11.74, B:0.92, C:4.50, D:3.73, E:11.79, F:0.95, G:1.64, H:1.54, I:10.14,
  J:0.00, K:0.00, L:6.51, M:2.51, N:6.88, O:9.83, P:3.05, Q:0.51, R:6.37,
  S:4.98, T:5.62, U:3.01, V:2.10, W:0.00, X:0.00, Y:0.00, Z:1.18
};

function chiSquared(obsPerc) {
  let chi = 0;
  const eps = 1e-6;
  for (const L of Object.keys(ITALIAN_FREQ)) {
    const expected = ITALIAN_FREQ[L];
    const observed = obsPerc[L] || 0;
    chi += ((observed - expected) ** 2) / Math.max(expected, eps);
  }
  return chi;
}

function bestShiftByFrequency(cipher) {
  // prova tutti gli shift 0..25 (decifratura): pick min chi^2
  let best = { shift: 0, chi: Infinity, plain: cipher };
  for (let k = 0; k < 26; k++) {
    const dec = caesarShift(cipher, (26 - k) % 26);
    const { perc } = freqCount(dec);
    const chi = chiSquared(perc);
    if (chi < best.chi) best = { shift: (26 - k) % 26, chi, plain: dec };
  }
  return best; // shift tale che ENC(plain, shift) = cipher
}

function toCSV(counts, perc, total) {
  const letters = Object.keys(counts);
  let csv = 'Letter,Count,Percent\n';
  for (const L of letters) {
    csv += `${L},${counts[L]},${perc[L].toFixed(2)}\n`;
  }
  csv += `TOTAL,${total},100.00\n`;
  return csv;
}

function writeText(p, data) {
  fs.writeFileSync(p, data, 'utf8');
}

// ===================== Main =====================
(function main() {
  const { input, shift, outdir } = parseArgs();
  ensureDir(outdir);

  const raw = fs.readFileSync(input, 'utf8');
  const norm = normalizeText(raw);
  const { counts: srcCounts, perc: srcPerc, n: nSrc } = freqCount(norm);

  const cipher = caesarShift(norm, shift);
  const { counts: cipCounts, perc: cipPerc, n: nCip } = freqCount(cipher);

  const best = bestShiftByFrequency(cipher); // trova shift e plaintext
  const detectedShift = best.shift; // quanto servirebbe a cifrare
  const dec = best.plain;

  // Scrive file di output
  writeText(path.join(outdir, 'source_normalized.txt'), norm);
  writeText(path.join(outdir, 'ciphertext.txt'), cipher);
  writeText(path.join(outdir, 'decrypted.txt'), dec);
  writeText(path.join(outdir, 'source_freq.csv'), toCSV(srcCounts, srcPerc, nSrc));
  writeText(path.join(outdir, 'cipher_freq.csv'), toCSV(cipCounts, cipPerc, nCip));

  // Report Markdown (da incollare nel blog)
  const md = [
    '# Risultati analisi Cesare (offline)',
    `- File sorgente: **${path.basename(input)}**`,
    `- Normalizzazione: solo lettere A–Z (accenti rimossi), N = **${nSrc}**`,
    `- Shift usato per cifrare: **${shift}**`,
    `- Shift stimato via frequenze (chi²): **${detectedShift}**`,
    '',
    '## Estratti',
    '### Ciphertext',
    '```',
    cipher.slice(0, 800),
    cipher.length > 800 ? '\n[...]' : '',
    '```',
    '### Plaintext (decifrato)',
    '```',
    dec.slice(0, 800),
    dec.length > 800 ? '\n[...]' : '',
    '```',
    '',
    '## File generati',
    '- `output/source_normalized.txt`',
    '- `output/ciphertext.txt`',
    '- `output/decrypted.txt`',
    '- `output/source_freq.csv`',
    '- `output/cipher_freq.csv`',
    '',
    '_Nota: con testi molto brevi l’analisi di frequenza può essere imprecisa. Usare testi più lunghi migliora lo stimatore._'
  ].join('\n');

  writeText(path.join(outdir, 'report.md'), md);

  // Stampa riepilogo su console
  console.log('✓ Analisi completata.');
  console.log(`- Input: ${input}`);
  console.log(`- Output dir: ${outdir}`);
  console.log(`- Shift cifratura: ${shift}`);
  console.log(`- Shift stimato (chi²): ${detectedShift}`);
  console.log('> Copia/incolla da output/report.md nella pagina del blog.');
})();
