'use strict';
// Builds the second corpus: every Macho directory that holds a .fxap is
// decrypted into decompiler output under verify\work\macho, then the current
// cleanup pass produces the matching Output_clean.
//
// The Macho tree stores assets still sealed with the FXAP magic, so nothing
// there can be measured until it has been through the decryptor; this is the
// same route the existing luacbatch.js took.
//
// Nothing in the Macho tree is written to. Each resource is copied into this
// script's own work directory first.
//
// usage: node build_macho_corpus.js [--root <dir>] [--work <dir>] [--max N]

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const HERE = __dirname;
const TMP = path.resolve(path.join(HERE, '..'));
const DREC = 'C:\\Users\\Admin\\Desktop\\drecrpy';
const HARNESS = path.join(TMP, 'harness.exe');
const PASS = path.join(HERE, 'bin', 'pass.exe');
const ROOT = argValue('--root', 'C:\\Users\\Admin\\Documents\\Macho');
const WORK = path.resolve(argValue('--work', path.join(HERE, 'work', 'macho')));
const MAX = Number(argValue('--max', '0')) || Infinity;

function argValue(flag, fallback) {
    const i = process.argv.indexOf(flag);
    return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

function findResourceDirs(root) {
    const out = [];
    const walk = (dir) => {
        let entries;
        try {
            entries = fs.readdirSync(dir, { withFileTypes: true });
        } catch {
            return;
        }
        if (entries.some((e) => e.isFile() && e.name === '.fxap')) out.push(dir);
        for (const e of entries) {
            if (e.isDirectory()) walk(path.join(dir, e.name));
        }
    };
    walk(root);
    return out.sort((a, b) => a.localeCompare(b));
}

function safeName(name) {
    return name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 60);
}

function luaCount(dir) {
    if (!fs.existsSync(dir)) return 0;
    let n = 0;
    const walk = (p) => {
        for (const e of fs.readdirSync(p, { withFileTypes: true })) {
            const q = path.join(p, e.name);
            if (e.isDirectory()) walk(q);
            else if (e.name.endsWith('.lua')) n++;
        }
    };
    walk(dir);
    return n;
}

function main() {
    if (!fs.existsSync(HARNESS)) {
        console.error('missing ' + HARNESS + ' (the decrypt harness); cannot build the second corpus');
        process.exit(2);
    }
    if (!fs.existsSync(PASS)) {
        console.error('missing ' + PASS + '; run build_pass.bat first');
        process.exit(2);
    }
    const refGrants = JSON.parse(fs.readFileSync(path.join(DREC, 'grants.json'), 'utf8'));
    const { scanResourceId, decryptOuterBuffer } = require(path.join(DREC, 'src', 'crypto.js'));

    const dirs = findResourceDirs(ROOT);
    fs.mkdirSync(WORK, { recursive: true });

    const index = { root: ROOT, work: WORK, resources: [], skipped: [], files: 0 };
    let built = 0;

    for (const src of dirs) {
        if (built >= MAX) break;
        const label = path.basename(src);
        let id;
        try {
            id = scanResourceId(decryptOuterBuffer(fs.readFileSync(path.join(src, '.fxap'))));
        } catch (e) {
            index.skipped.push({ name: label, why: '.fxap unreadable: ' + e.message });
            continue;
        }
        const grant = refGrants.grants[id];
        if (!grant || !refGrants.grants_clk[id]) {
            index.skipped.push({ name: label, id, why: 'no grant in drecrpy/grants.json' });
            continue;
        }

        const slot = String(built).padStart(2, '0') + '_' + safeName(label);
        const cwd = path.join(WORK, slot);
        fs.rmSync(cwd, { recursive: true, force: true });
        const serverRoot = path.join(cwd, 'Servers', slot);
        const grantsFile = path.join(serverRoot, 'Resources', 'Grants.txt');
        fs.mkdirSync(path.dirname(grantsFile), { recursive: true });
        fs.writeFileSync(grantsFile, 'x.' + Buffer.from(JSON.stringify({
            grants: { [id]: grant },
            grants_clk: { [id]: refGrants.grants_clk[id] },
        })).toString('base64') + '.y');
        fs.cpSync(src, path.join(serverRoot, 'Unpacked', label), { recursive: true });

        let note = '';
        let decryptNote = '';
        // The decryptor exits non-zero when any single script failed, which still
        // leaves usable output for the rest. Run the pass on whatever landed.
        try {
            execFileSync(HARNESS, [slot], { cwd, stdio: 'pipe' });
        } catch (e) {
            decryptNote = 'decryptor reported: ' + String(e.message).split('\n')[0].slice(0, 120);
        }
        const outDir = path.join(serverRoot, 'Output');
        if (!fs.existsSync(outDir)) {
            note = decryptNote || 'decrypt produced no Output directory';
        } else {
            try {
                execFileSync(PASS, [outDir, path.join(serverRoot, 'Output_clean')], { stdio: 'pipe' });
            } catch (e) {
                note = 'cleanup pass failed: ' + String(e.message).slice(0, 200);
            }
            if (note) {
                decryptNote = decryptNote || note;
            }
        }
        const n = luaCount(outDir);
        if (!note && n === 0) note = 'decrypt produced no lua';
        built++;
        const rec = { slot, name: label, id, source: src, files: n, note, decryptNote };
        index.resources.push(rec);
        index.files += n;
        console.log((note ? 'SKIP ' : 'OK   ') + slot.padEnd(34) + String(n).padStart(5) + '  ' +
            (note || label));
    }

    fs.writeFileSync(path.join(WORK, 'index.json'), JSON.stringify(index, null, 1));
    const usable = index.resources.filter((r) => !r.note);
    console.log(`\nbuilt ${usable.length} resource(s), ${index.files} lua file(s), ` +
        `skipped ${index.skipped.length}`);
    console.log('index: ' + path.join(WORK, 'index.json'));
    for (const s of index.skipped) console.log(`  skipped ${s.name}: ${s.why}`);
}

main();