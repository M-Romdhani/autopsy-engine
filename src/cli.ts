#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { basename } from 'node:path'
import { parseArgs } from 'node:util'
import { analyzeDocument, comparePdfs } from './analyze.js'

const USAGE = `Usage:
  autopsy analyze <file.pdf|file.docx> [--json] [--local]
  autopsy compare <original.pdf> <suspect.pdf> [--json]

Options:
  --json    Print the full result as JSON
  --local   Never call Gemini, even if GEMINI_API_KEY is set

Set GEMINI_API_KEY (and optionally GEMINI_MODEL) to add an AI pass on top of the
local analysis. The document's text is then sent to Google's Gemini API.`

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean', default: false },
      local: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })
  const [command, ...files] = positionals
  if (values.help || !command) {
    console.log(USAGE)
    return command || values.help ? 0 : 1
  }

  if (command === 'analyze' && files.length === 1) {
    const result = await analyzeDocument(await readFile(files[0]), {
      fileName: basename(files[0]),
      ai: values.local ? false : undefined,
    })
    if (values.json) console.log(JSON.stringify(result, null, 2))
    else printAnalysis(basename(files[0]), result)
    return 0
  }

  if (command === 'compare' && files.length === 2) {
    const [original, suspect] = await Promise.all(files.map((f) => readFile(f)))
    const result = comparePdfs(original, suspect, { original: basename(files[0]), suspect: basename(files[1]) })
    if (values.json) console.log(JSON.stringify(result, null, 2))
    else printComparison(result)
    return 0
  }

  console.error(USAGE)
  return 1
}

function printAnalysis(name: string, { report, compliance }: Awaited<ReturnType<typeof analyzeDocument>>): void {
  const auth = report.authenticityAnalysis
  console.log(`${name}  (${report.documentClassification.type}, engine ${report.analysisVersion})`)
  if (auth) console.log(`Authenticity: ${auth.overallScore}/100 — ${auth.verdict}, ${auth.fraudRiskLevel} fraud risk`)
  console.log(`Integrity:    ${Math.round(report.integrityAssessment.overallScore * 100)}/100`)
  console.log(`Compliance:   ${compliance.overall}/100 (grade ${compliance.grade})`)
  const forensic = report.pdfForensicAnalysis
  if (forensic) console.log(`PDF forensics: ${forensic.overallScore}/100 — ${forensic.verdict}, ${forensic.riskLevel} risk`)

  const flags = [
    ...(auth?.redFlags ?? []).map((f) => `[${f.severity}] ${f.title}: ${f.description}`),
    ...(forensic?.redFlags ?? []).map((f) => `[${f.severity}] ${f.title}: ${f.description}`),
  ]
  if (flags.length) {
    console.log('\nRed flags:')
    for (const flag of flags) console.log(`  - ${flag}`)
  }
  if (compliance.recommendations.length) {
    console.log('\nRecommendations:')
    for (const rec of compliance.recommendations) console.log(`  - ${rec}`)
  }
}

function printComparison(result: ReturnType<typeof comparePdfs>): void {
  console.log(`Verdict: ${result.verdict} (${result.overallRisk} risk)`)
  const { comparison } = result
  console.log(`Size ratio: ${comparison.sizeRatio.toFixed(2)}x, links ${comparison.linkDifference >= 0 ? '+' : ''}${comparison.linkDifference}`)
  if (comparison.fontDifferences.added.length) console.log(`Fonts added: ${comparison.fontDifferences.added.join(', ')}`)
  if (comparison.fontDifferences.removed.length) console.log(`Fonts removed: ${comparison.fontDifferences.removed.join(', ')}`)
  for (const diff of comparison.structuralDifferences) console.log(`  - ${diff}`)
  for (const rec of result.recommendations) console.log(`  > ${rec}`)
}

main().then(
  (code) => process.exit(code),
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : error)
    process.exit(1)
  },
)
