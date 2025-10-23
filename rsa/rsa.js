#!/usr/bin/env node
/**
 * rsa_freq.js — RSA per-lettera + attacco di ricorrenza basato sul plaintext
 * Uso:
 *   node rsa.js --in input.txt --p 13 --q 11 --e 7
 *
 * Output in ./output:
 *   normalized_plain.txt, ciphertext.txt, decrypted.txt
 *   attack_guess_from_source.txt
 *   mapping.txt, source_freq.csv, cipher_freq.csv, guess_freq.csv, report.txt
 */

const fs = require('fs');
const path = require('path');

/* ---------------------- CLI ---------------------- */
function parseArgs()
{
  const out = {};
  const a = process.argv.slice(2);
  for (let i = 0; i < a.length; i++)
  {
    if (!a[i].startsWith('--')) continue;
    const k = a[i].slice(2);
    const v = a[i + 1];
    if (!v || v.startsWith('--')) out[k] = true; else { out[k] = v; i++; }
  }
  return out;
}

/* ---------------- Normalizzazione A–Z ---------------- */
function onlyAZ(s)
{
  return s.normalize('NFKD')
          .replace(/[\u0300-\u036f]/g, '')
          .toUpperCase()
          .replace(/[^A-Z]/g, '');
}

/* ------------------- Frequenze ------------------- */
function countFreqAZ(s)
{
  const f = Array(26).fill(0);
  for (const ch of s)
  {
    const i = ch.charCodeAt(0) - 65;
    if (i >= 0 && i < 26) f[i]++;
  }
  return f;
}

function freqToCSV(freq)
{
  let out = 'letter,freq\n';
  for (let i = 0; i < 26; i++) out += `${String.fromCharCode(65 + i)},${freq[i]}\n`;
  return out;
}

/* Ordina le lettere per frequenza (desc), tie-break alfabetico */
function orderByFreq(textAZ)
{
  const f = countFreqAZ(textAZ);
  const idx = [...Array(26).keys()].sort((a, b) => (f[b] - f[a]) || (a - b));
  return idx.map(i => String.fromCharCode(65 + i));
}

/* Applica una sostituzione letterale */
function applySubst(textAZ, map)
{
  let out = '';
  for (const ch of textAZ) out += map.get(ch) || '?';
  return out;
}

/* ---------------- Aritmetica modulare (BigInt) ---------------- */
function egcdBig(a, b)
{
  a = BigInt(a); b = BigInt(b);
  if (b === 0n) return { g:a, x:1n, y:0n };
  const r = egcdBig(b, a % b);
  return { g:r.g, x:r.y, y:r.x - (a / b) * r.y };
}

function modInvBig(e, phi)
{
  const { g, x } = egcdBig(e, phi);
  if (g !== 1n) throw new Error('e e φ non coprimi');
  return (x % phi + phi) % phi;
}

function modPowBig(base, exp, mod)
{
  let b = BigInt(base) % BigInt(mod);
  let e = BigInt(exp);
  const m = BigInt(mod);
  let r = 1n;
  while (e > 0n)
  {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

/* ---------------- RSA per-lettera (mappa 1:1) ---------------- */
function buildPlainToNumMap(p, q, e)
{
  const n = BigInt(p) * BigInt(q);
  const map = new Map(); // 'A' -> BigInt(c)
  for (let m = 0; m < 26; m++)
  {
    map.set(String.fromCharCode(65 + m), modPowBig(BigInt(m), BigInt(e), n));
  }
  const uniq = Array.from(new Set([...map.values()].map(v => v.toString()))).map(s => BigInt(s));
  if (uniq.length !== 26)
  {
    throw new Error(`m^e mod n produce ${uniq.length} residui (serve 26). Usa p=13 q=11 e=7 o parametri equivalenti.`);
  }
  uniq.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { n, map, uniq };
}

function buildSymbolMaps(mapPlainToNum, uniq)
{
  const numToSym = new Map();
  for (let i = 0; i < 26; i++) numToSym.set(uniq[i].toString(), String.fromCharCode(65 + i));

  const plainToSym = new Map();
  for (const [L, num] of mapPlainToNum.entries()) plainToSym.set(L, numToSym.get(num.toString()));

  const symToNum = new Map();
  for (const [numStr, sym] of numToSym.entries()) symToNum.set(sym, BigInt(numStr));

  return { numToSym, plainToSym, symToNum };
}

/* --------------------------- MAIN --------------------------- */
(async function main()
{
  try
  {
    const args = parseArgs();
    if (!args.in)
    {
      console.error('Uso: node rsa_freq.js --in input.txt [--p 13 --q 11 --e 7]');
      process.exit(1);
    }

    const p = parseInt(args.p || '13', 10);
    const q = parseInt(args.q || '11', 10);
    const e = parseInt(args.e || '7', 10);

    const outdir = path.join(process.cwd(), 'output');
    fs.mkdirSync(outdir, { recursive:true });

    const raw = fs.readFileSync(args.in, 'utf8');
    const plainAZ = onlyAZ(raw);
    if (!plainAZ.length) throw new Error('Nessuna lettera A–Z dopo normalizzazione.');

    const { n, map, uniq } = buildPlainToNumMap(p, q, e);
    const { numToSym, plainToSym, symToNum } = buildSymbolMaps(map, uniq);

    // Cifratura (permutazione deterministica 1:1)
    const cipherAZ = [...plainAZ].map(ch => plainToSym.get(ch)).join('');

    // Decifratura (verifica)
    const phi = BigInt((p - 1) * (q - 1));
    const d = modInvBig(BigInt(e), phi);
    const encNums = [...cipherAZ].map(sym => symToNum.get(sym));
    const decAZ = encNums.map(c => String.fromCharCode(65 + Number(modPowBig(c, d, BigInt(n))))).join('');

    // Attacco di ricorrenza basato sul plaintext:
    // allineo l’ordine di frequenza del ciphertext all’ordine di frequenza del plaintext
    const srcOrder    = orderByFreq(plainAZ);   // es. ['E','A','I',...]
    const cipherOrder = orderByFreq(cipherAZ);  // es. ['N','J','A',...]

    const mapCipherToPlainByRank = new Map();
    for (let i = 0; i < 26; i++) mapCipherToPlainByRank.set(cipherOrder[i], srcOrder[i]);

    const guessAZ = applySubst(cipherAZ, mapCipherToPlainByRank);

    // Statistiche
    const srcF = countFreqAZ(plainAZ);
    const cifF = countFreqAZ(cipherAZ);
    const gueF = countFreqAZ(guessAZ);
    const acc  = ([...plainAZ].reduce((k, ch, i) => k + (ch === guessAZ[i] ? 1 : 0), 0) / plainAZ.length) * 100;

    // Scritture
    fs.writeFileSync(path.join(outdir, 'normalized_plain.txt'), plainAZ, 'utf8');
    fs.writeFileSync(path.join(outdir, 'ciphertext.txt'),        cipherAZ, 'utf8');
    fs.writeFileSync(path.join(outdir, 'decrypted.txt'),         decAZ,    'utf8');
    fs.writeFileSync(path.join(outdir, 'attack_guess_from_source.txt'), guessAZ, 'utf8');

    let mapping = 'Plain,Num(m^e mod n),Symbol\n';
    for (const [L, num] of map.entries()) mapping += `${L},${num.toString()},${plainToSym.get(L)}\n`;
    fs.writeFileSync(path.join(outdir, 'mapping.txt'), mapping, 'utf8');

    fs.writeFileSync(path.join(outdir, 'source_freq.csv'), freqToCSV(srcF), 'utf8');
    fs.writeFileSync(path.join(outdir, 'cipher_freq.csv'), freqToCSV(cifF), 'utf8');
    fs.writeFileSync(path.join(outdir, 'guess_freq.csv'),  freqToCSV(gueF), 'utf8');

    const report = [
      '=== RSA per-lettera — report (attacco basato su ricorrenza del plaintext) ===',
      `Input normalizzato (len): ${plainAZ.length}`,
      `Parametri: p=${p}, q=${q}, n=${(BigInt(p)*BigInt(q)).toString()}, φ=${phi.toString()}, e=${e}, d=${d.toString()}`,
      `Residui distinti m^e mod n: ${uniq.length} (richiesti: 26)`,
      `Accuratezza stima (rank matching): ${acc.toFixed(2)}%`,
      'File: normalized_plain.txt, ciphertext.txt, decrypted.txt, attack_guess_from_source.txt, mapping.txt, *.csv'
    ].join('\n');
    fs.writeFileSync(path.join(outdir, 'report.txt'), report, 'utf8');

    console.log('✓ File scritti in ./output');
    console.log(`Accuratezza (rank plaintext vs cipher): ${acc.toFixed(2)}%`);
  }
  catch (err)
  {
    console.error('Errore:', err.message);
    process.exit(1);
  }
})();
