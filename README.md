# Autopsy Engine

Document forensics for PDF and DOCX files. Autopsy Engine reads a document's
metadata, text and raw structure, reconstructs its edit history, and reports how
likely it is to have been tampered with, with the evidence behind each finding.

It is built for the documents people forge most: invoices, receipts, bank
statements and contracts.

```
$ autopsy analyze suspect.pdf
suspect.pdf  (Invoice, engine 2.2.0-local)
Authenticity: 94/100 — authentic, low fraud risk
Integrity:    85/100
Compliance:   84/100 (grade B)
PDF forensics: 77/100 — likely_authentic, medium risk

Red flags:
  - [high] Document Modified After Creation: Document was modified 1093 hours after creation
  - [medium] Multiple Save Operations Detected: Document was saved 2 times (incremental updates)
  - [high] PDF Editing Tool Detected: Document shows signs of being edited with: ilovepdf
```

Everything runs locally. An optional Gemini pass can add a summary and extra
findings on top.

## What it checks

**PDF structure** (read from the raw bytes, independent of any parser)
- Incremental updates: every extra `%%EOF` is another save on top of the original
- Editing-tool signatures in every Producer and Creator entry, including ones an
  editor appended later (iLovePDF, Smallpdf, Sejda, PDFescape, Foxit, Nitro, …)
- Fonts: subset fonts and fonts typical of after-the-fact edits
- Timestamps: modification long after creation, dates in the future, missing dates
- Links: financial documents with no links can indicate a print-to-PDF re-render
- File size against a reference copy, when you have one (see `compare`)

**Metadata and content**
- Creation and modification dates, author, software and revision count for PDF
  and DOCX (`docProps/core.xml`, `docProps/app.xml`), checked for consistency
- A reconstructed timeline of edit events, each with its suspicious flags
- Financial documents: amounts that do not add up, mixed currencies, mixed date
  formats, copy-paste artifacts, odd capitalization
- Document type (invoice, receipt, contract, report, letter, statement), key
  topics, tone, and suspicious phrases common in payment fraud

**Comparison**
- `compare` puts a known-good PDF next to a suspect copy: size ratio, added or
  removed fonts, extra saves, new editing markers, link differences

**Scores**
- Authenticity, integrity and compliance scores (0–100), a verdict, a risk level
  and recommendations

These are signals for a human reviewer, not proof. A clean report does not
certify a document, and a flag does not prove fraud.

## Install

Requires Node.js 18.17 or later.

```bash
npm install github:M-Romdhani/autopsy-engine
```

or from a clone:

```bash
git clone https://github.com/M-Romdhani/autopsy-engine.git
cd autopsy-engine
npm install          # also builds dist/
npm link             # optional: puts `autopsy` on your PATH
```

## Command line

```bash
autopsy analyze invoice.pdf              # human-readable report
autopsy analyze contract.docx --json     # full report as JSON
autopsy analyze invoice.pdf --local      # never call Gemini, even with a key set
autopsy compare original.pdf suspect.pdf
```

Without `npm link`, run `node dist/cli.js` in place of `autopsy`.

## Library

```ts
import { readFile } from 'node:fs/promises'
import { analyzeDocument, comparePdfs } from 'autopsy-engine'

const buffer = await readFile('invoice.pdf')
const { report, events, metadata, compliance } = await analyzeDocument(buffer, {
  fileName: 'invoice.pdf',
  ai: false, // fully local; omit to use GEMINI_API_KEY when it is set
})

console.log(report.authenticityAnalysis?.verdict, report.pdfForensicAnalysis?.redFlags)

const diff = comparePdfs(await readFile('original.pdf'), buffer)
console.log(diff.verdict, diff.comparison.structuralDifferences)
```

The individual stages are exported too: `extractPdfMetadata`,
`extractDocxMetadata`, `analyzePDFForensics`, `generateAuthenticityAnalysis`,
`analyzeFinancialDocument`, `calculateComplianceScore`, `computeTextDiff`, and
the full TypeScript types of the report.

## Optional AI pass

| Variable | Default | |
|---|---|---|
| `GEMINI_API_KEY` | unset | Enables the Gemini pass |
| `GEMINI_MODEL` | `gemini-2.5-flash` | Any Gemini model that supports `generateContent` |

With a key set, the document's extracted text and the local findings are sent to
Google's Gemini API, which adds a summary, topics and further suspicious patterns.
The local analysis always runs first and stands on its own; if the call fails,
the report is the local one. Use `--local` or `ai: false` for documents that must
not leave the machine. You can also pass `ai: { apiKey, model }` in code.

## Development

```bash
npm install
npm test             # vitest; PDFs and DOCX files are generated in the tests
npm run typecheck
npm run build
```

```
src/
  analyze.ts         analyzeDocument / comparePdfs: the pipeline
  cli.ts             the `autopsy` command
  metadata/          PDF (pdf-parse) and DOCX (mammoth + docProps) extraction
  forensics/         raw-byte PDF forensics and two-file comparison
  authenticity/      metadata, content and financial-document checks
  ai/                classification, content analysis, edit timeline, optional Gemini pass
  compliance/        compliance score and recommendations
  diff/              text diff and similarity
  types.ts           report types
test/                tests and the PDF / DOCX fixture builders
```

## License

[Apache-2.0](LICENSE)
