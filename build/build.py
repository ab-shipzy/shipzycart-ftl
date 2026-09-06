#!/usr/bin/env python3
"""Builds dist/public/index.html from src/ — used locally and by GitHub Actions."""
import re, subprocess, sys, os, shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, "src", "shipzy_dashboard.jsx")
TPL  = os.path.join(ROOT, "src", "template.html")
OUT_DIR = os.path.join(ROOT, "dist", "public")

src = open(SRC).read()
m = re.search(r'const BUILD_VERSION = "([^"]+)"', src)
ver = m.group(1) if m else "unknown"
print(f"Building {ver}")

stripped = re.sub(r'^import\s[^;]*?from\s+"[^"]+";', '', src, flags=re.M | re.S)
stripped = stripped.replace('export default function App()', 'function App()')
stripped = re.sub(r'^export ', '', stripped, flags=re.M)
open(os.path.join(ROOT, "build", "_stripped.jsx"), "w").write(stripped)
print(f"  Stripped: {len(stripped):,}")

r = subprocess.run(["node", os.path.join(ROOT, "build", "precompile.mjs")],
                   capture_output=True, text=True, cwd=os.path.join(ROOT, "build"))
if r.returncode != 0:
    print("BABEL ERROR:\n", r.stderr[:3000]); sys.exit(1)
compiled = open(os.path.join(ROOT, "build", "_compiled.js")).read()
compiled = compiled.replace("</script>", "<\\/script>")
print(f"  Pre-compiled: {len(compiled):,}")

tpl = open(TPL).read()
assert "/*__APP_CODE__*/" in tpl, "marker missing in template"
html = tpl.replace("/*__APP_CODE__*/", compiled)

os.makedirs(OUT_DIR, exist_ok=True)
open(os.path.join(OUT_DIR, "index.html"), "w").write(html)

extra = os.path.join(ROOT, "public-extra")
for name in os.listdir(extra):
    s = os.path.join(extra, name)
    d = os.path.join(OUT_DIR, name)
    if os.path.isdir(s): shutil.copytree(s, d, dirs_exist_ok=True)
    else: shutil.copy2(s, d)

print(f"  wrote dist/public/index.html ({len(html):,} bytes) + PWA files")
