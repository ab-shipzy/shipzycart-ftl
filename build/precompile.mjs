import { createRequire } from 'module';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const babel = require('@babel/core');
const src = fs.readFileSync(path.join(__dirname, '_stripped.jsx'), 'utf8');
const out = babel.transformSync(src, {
  presets: [[require('@babel/preset-react'), { runtime: 'classic' }]],
  compact: false, comments: true, babelrc: false, configFile: false,
});
fs.writeFileSync(path.join(__dirname, '_compiled.js'), out.code);
console.log('compiled', out.code.length);
