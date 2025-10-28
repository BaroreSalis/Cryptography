// rsa_attack.js (aggiornato per creare file in ./output)
// Node.js script didattico: RSA per-lettera + attacco tramite analisi di frequenza + hill-climbing (bigram)
// Usage: node rsa_attack_with_output.js "your plaintext here"
// Default: if no argument, uses a builtin sample paragraph.
'use strict';
const fs = require('fs');
const path = require('path');

// MCD or EGCD function
function egcd(a, b) {
  if (b === 0n) return [1n, 0n, a];
  const [x1, y1, g] = egcd(b, a % b);
  return [y1, x1 - (a / b) * y1, g];
}

// Modular Inverse Function
function modInv(a, m) {
  const [x, y, g] = egcd(a, m);
  if (g !== 1n) throw new Error("No modular inverse");
  return ((x % m) + m) % m;
}

function modPow(base, exp, mod) {
  base = ((base % mod) + mod) % mod;
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}

// Alfabeto parameters
const ALPHABET = [];
for (let i = 0; i < 26; i++) ALPHABET.push(String.fromCharCode(65 + i));
ALPHABET.push(' '); // spazio come carattere aggiuntivo

const CHAR2INT = {};
ALPHABET.forEach((c, i) => CHAR2INT[c] = i);

const INT2CHAR = {};
Object.keys(CHAR2INT).forEach(k => INT2CHAR[CHAR2INT[k]] = k);

// Normalizzazione semplice
function normalizeText(s) {
  s = String(s).toUpperCase();
  let out = '';
  let prevSpace = false;
  for (const ch of s) {
    if (ch >= 'A' && ch <= 'Z') {
      out += ch;
      prevSpace = false;
    } else if (ch === ' ') {
      if (!prevSpace) {
        out += ' ';
        prevSpace = true;
      }
    }
  }
  return out.trim();
}

// Creazione parametri RSA piccoli (didattici)
function makeSmallRSA(p = 101n, q = 113n, e = 17n) {
  const N = p * q;
  const phi = (p - 1n) * (q - 1n);
  if (gcd(e, phi) !== 1n) throw new Error("e must be coprime with phi");
  const d = modInv(e, phi);
  return { p, q, N, e, d, phi };
}

function gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) {
    const t = a % b;
    a = b;
    b = t;
  }
  return a;
}

// Cifratura/decifratura per-lettera
function encryptTextRSA(text, pub) {
  // Restituisce un array di simboli
  const res = [];
  for (const ch of text) {
    if (!(ch in CHAR2INT)) {
      res.push(null);
      continue;
    } // preserva spazi non mappati se serve
    const m = BigInt(CHAR2INT[ch]);
    const c = modPow(m, pub.e, pub.N);
    res.push(c);
  }
  return res;
}

function decryptTextRSA(cipherArr, priv) {
  const out = [];
  for (const c of cipherArr) {
    if (c === null) {
      out.push('?');
      continue;
    }
    const m = modPow(c, priv.d, priv.N);
    out.push(INT2CHAR[Number(m)]);
  }
  return out.join('');
}

// Conteggi e mapping per frequenza
function countsFromArray(arr) {
  const cnt = new Map();
  for (const x of arr) {
    if (x === null) continue;
    const key = x.toString();
    cnt.set(key, (cnt.get(key) || 0) + 1);
  }
  return cnt;
}

function sortMapByValueDesc(map) {
  return Array.from(map.entries()).sort((a, b) => b[1] - a[1]).map(x => x[0]);
}

// Costruzione iniziale della mappa delle frequenze
function freqMapping(cipherNums, plainCounts, rsaPub) {
  const expectedCipherSymbols = [];
  for (let i = 0; i < ALPHABET.length; i++) {
    expectedCipherSymbols.push(modPow(BigInt(i), rsaPub.e, rsaPub.N));
  }

  const cCounts = countsFromArray(cipherNums);
  const arr = expectedCipherSymbols.map(sym => [sym, cCounts.get(sym.toString()) || 0]);
  arr.sort((a, b) => b[1] - a[1]);

  const plainList = Object.entries(plainCounts)
    .sort((a, b) => b[1] - a[1])
    .map(x => x[0]);

  for (const c of ALPHABET) if (!plainList.includes(c)) plainList.push(c);

  const mapping = new Map();
  for (let i = 0; i < expectedCipherSymbols.length; i++) {
    mapping.set(arr[i][0].toString(), plainList[i]);
  }
  return mapping;
}

function applyMappingToCipher(cipherNums, mapping) {
  const out = [];
  for (const c of cipherNums) {
    if (c === null) {
      out.push('?');
      continue;
    }
    const letter = mapping.get(c.toString()) || '?';
    out.push(letter);
  }
  return out.join('');
}

function buildBigramModelFromText(text) {
  const bigramCounts = {};
  let total = 0;
  for (let i = 0; i < text.length - 1; i++) {
    const a = text[i], b = text[i + 1];
    if (CHAR2INT[a] !== undefined && CHAR2INT[b] !== undefined) {
      const key = a + b;
      bigramCounts[key] = (bigramCounts[key] || 0) + 1;
      total++;
    }
  }
  const V = ALPHABET.length;
  const model = {};
  for (const a of ALPHABET) {
    for (const b of ALPHABET) {
      const key = a + b;
      const cnt = (bigramCounts[key] || 0) + 1; // add-1 smoothing
      model[key] = Math.log(cnt / (total + V * V));
    }
  }
  return model;
}

function scoreMapping(mapping, cipherNums, bigramModel) {
  const decoded = applyMappingToCipher(cipherNums, mapping);
  let score = 0;
  for (let i = 0; i < decoded.length - 1; i++) {
    const a = decoded[i], b = decoded[i + 1];
    if (CHAR2INT[a] !== undefined && CHAR2INT[b] !== undefined) score += bigramModel[a + b];
  }
  return score;
}

function hillClimb(mapping, cipherNums, bigramModel, rsaPub, iterations = 2000) {
  const expected = [];
  for (let i = 0; i < ALPHABET.length; i++) expected.push(modPow(BigInt(i), rsaPub.e, rsaPub.N).toString());

  const assigned = new Set(Array.from(mapping.values()));
  let remainingLetters = ALPHABET.filter(c => !assigned.has(c));
  for (const sym of expected) {
    if (!mapping.has(sym)) mapping.set(sym, remainingLetters.length ? remainingLetters.pop() : ALPHABET[0]);
  }

  let bestScore = scoreMapping(mapping, cipherNums, bigramModel);
  const syms = expected.slice();

  for (let it = 0; it < iterations; it++) {
    const i = Math.floor(Math.random() * syms.length);
    let j = Math.floor(Math.random() * syms.length);
    if (i === j) continue;
    const a = syms[i], b = syms[j];
    const ma = mapping.get(a), mb = mapping.get(b);
    mapping.set(a, mb);
    mapping.set(b, ma);
    const newScore = scoreMapping(mapping, cipherNums, bigramModel);
    if (newScore > bestScore) {
      bestScore = newScore;
    } else {
      mapping.set(a, ma);
      mapping.set(b, mb);
    }
  }
  return bestScore;
}

function accuracy(decoded, plaintext) {
  let tot = 0, corr = 0;
  for (let i = 0; i < Math.min(decoded.length, plaintext.length); i++) {
    const t = plaintext[i];
    if (CHAR2INT[t] === undefined) continue;
    tot++;
    if (decoded[i] === t) corr++;
  }
  return { tot, corr, acc: tot ? (corr / tot) : 0 };
}

// --- helper IO functions ---
function ensureOutputDir() {
  const out = path.join(process.cwd(), 'output');
  fs.mkdirSync(out, { recursive: true });
  return out;
}

function writeCSV(filePath, rows, header = ['letter', 'freq']) {
  const lines = [header.join(',')];
  for (const r of rows) lines.push(`${r[0]},${r[1]}`);
  fs.writeFileSync(filePath, lines.join('\n'), 'utf8');
}

function countsObjectFromString(s) {
  const cnt = {};
  for (const ch of s) {
    if (CHAR2INT[ch] === undefined) continue;
    cnt[ch] = (cnt[ch] || 0) + 1;
  }
  return cnt;
}

// Main function
function main() {
    const args = process.argv.slice(2);
    const input = args.length ? args.join(' ') : "It was the best of times, it was the worst of times, it was the age of wisdom.";
    const plaintext = normalizeText(input);

    console.log("Plaintext normalized (len):", plaintext.length);

    // Scelta di primitive piccole
    const rsa = makeSmallRSA(101n, 113n, 17n);
    console.log("RSA params:", { p: rsa.p.toString(), q: rsa.q.toString(), N: rsa.N.toString(), e: rsa.e.toString(), d: rsa.d.toString() });

    // encrypt
    const cipherNums = encryptTextRSA(plaintext, rsa);
    console.log("Cipher length:", cipherNums.length, "distinct symbols:", new Set(cipherNums.map(x => x && x.toString())).size);

    // prepare plainCounts
    const plainCounts = {};
    for (const ch of plaintext) 
    {
        if (CHAR2INT[ch] !== undefined) plainCounts[ch] = (plainCounts[ch] || 0) + 1;
    }

    const mappingFreq = freqMapping(cipherNums, plainCounts, rsa);
    const decodedFreq = applyMappingToCipher(cipherNums, mappingFreq);
    const acc1 = accuracy(decodedFreq, plaintext);
    console.log(`Initial freq-decode accuracy: ${acc1.corr}/${acc1.tot} (${(acc1.acc * 100).toFixed(2)}%)`);
    console.log("Decoded sample (freq):", decodedFreq.slice(0, 200));

    const bigramModel = buildBigramModelFromText(plaintext);
    const beforeScore = scoreMapping(mappingFreq, cipherNums, bigramModel);
    const bestScore = hillClimb(mappingFreq, cipherNums, bigramModel, rsa, 3000);

    const decodedHill = applyMappingToCipher(cipherNums, mappingFreq);
    const acc2 = accuracy(decodedHill, plaintext);
    console.log(`Hill-climb: score before=${beforeScore.toFixed(2)}, after=${bestScore.toFixed(2)}`);
    console.log(`After hill-climb accuracy: ${acc2.corr}/${acc2.tot} (${(acc2.acc * 100).toFixed(2)}%)`);
    console.log("Decoded sample (hill):", decodedHill.slice(0, 200));

    console.log("\nSample mapping (cipherSymbol -> letter) (first 20):");
    let c = 0;
    for (const [k, v] of mappingFreq.entries()) {
        console.log(`${k} -> ${v}`);
        if (++c >= 20) break;
    }

    // --- Write requested files into ./output ---
    const outdir = ensureOutputDir();

    // 1) attack_guess_from_source.txt -> decrypted with the attack (decodedHill)
    fs.writeFileSync(path.join(outdir, 'attack_guess_from_source.txt'), decodedHill, 'utf8');

    // 2) cipher_freq.csv -> frequencies of the cipher symbols (symbol,freq) using columns letter,freq as requested
    const cipherCounts = countsFromArray(cipherNums); // Map of symbolStr -> count
    const cipherRows = Array.from(cipherCounts.entries()).sort((a,b)=>b[1]-a[1]);
    writeCSV(path.join(outdir, 'cipher_freq.csv'), cipherRows, ['letter','freq']);

    // 3) ciphertext.txt -> the ciphertext numbers
    const cipherTextLines = cipherNums.map(x => x === null ? 'NULL' : x.toString()).join(' ');
    fs.writeFileSync(path.join(outdir, 'ciphertext.txt'), cipherTextLines, 'utf8');

    // 4) decrypted.txt -> texte decrypted using la chiave privata (verifying correct decryption)
    const decryptedWithKey = decryptTextRSA(cipherNums, rsa);
    fs.writeFileSync(path.join(outdir, 'decrypted.txt'), decryptedWithKey, 'utf8');

    // 5) guess_freq.csv -> frequencies of letters of the plaintext decrypted with the attack (decodedHill)
    const guessCounts = countsObjectFromString(decodedHill);
    const guessRows = Object.entries(guessCounts).sort((a,b)=>b[1]-a[1]);
    writeCSV(path.join(outdir, 'guess_freq.csv'), guessRows, ['letter','freq']);

    // 6) mapping.txt -> mapping (cipherSymbol -> letter)
    const mapLines = [];
    for (const [k, v] of mappingFreq.entries()) mapLines.push(`${k} -> ${v}`);
    fs.writeFileSync(path.join(outdir, 'mapping.txt'), mapLines.join('\n'), 'utf8');

    // 7) source_freq.csv -> frequencies of letters of the plaintext normalized
    const sourceRows = Object.entries(plainCounts).sort((a,b)=>b[1]-a[1]);
    writeCSV(path.join(outdir, 'source_freq.csv'), sourceRows, ['letter','freq']);

    console.log(`\nWrote output files into ${outdir}:`);
    console.log('- attack_guess_from_source.txt (decrypted with attack)');
    console.log('- cipher_freq.csv (cipher symbol frequencies)');
    console.log('- ciphertext.txt (RSA ciphertext)');
    console.log('- decrypted.txt (decrypted with private key)');
    console.log('- guess_freq.csv (frequencies of attack-decoded plaintext)');
    console.log('- mapping.txt (cipherSymbol -> letter)');
    console.log('- source_freq.csv (frequencies of normalized source plaintext)');
}

if (require.main === module) 
{
    try 
    {
        main();
    } catch (err) 
    {
        console.error("Error:", err.message);
        console.error(err);
    }
}
