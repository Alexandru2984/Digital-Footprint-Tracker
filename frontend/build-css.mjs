#!/usr/bin/env node

// Builds tailwind.css from input.css.
//
// v4 moved the CLI into @tailwindcss/cli, which depends on @parcel/watcher and
// therefore on micromatch and braces — the unfixable advisory this migration
// exists to remove. The CLI is a file watcher wrapped around one compile call,
// and the build needs only the compile, so it runs the PostCSS plugin directly
// and minifies with the same lightningcss Tailwind already uses internally.

import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import postcss from 'postcss';
import tailwindcss from '@tailwindcss/postcss';
import { transform } from 'lightningcss';

const here = dirname(fileURLToPath(import.meta.url));
const input = join(here, 'input.css');
const output = join(here, 'tailwind.css');

const compiled = await postcss([tailwindcss()])
    .process(readFileSync(input, 'utf8'), { from: input, to: output });

const { code } = transform({
    filename: 'tailwind.css',
    code: Buffer.from(compiled.css),
    minify: true,
});

writeFileSync(output, code);
console.log(`build-css: wrote ${output} (${code.length} bytes)`);
