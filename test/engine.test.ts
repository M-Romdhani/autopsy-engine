import { describe, expect, it } from 'vitest'
import {
  analyzeDocument,
  analyzePDFForensics,
  calculateSimilarity,
  comparePdfs,
  detectFileType,
  DOCX_TYPE,
  extractDocxMetadata,
  extractPdfMetadata,
  PDF_TYPE,
} from '../src/index.js'
import { INVOICE_TEXT, makeDocx, makePdf } from './fixtures.js'

const clean = makePdf({
  text: INVOICE_TEXT,
  producer: 'Microsoft Word - Invoice',
  creator: 'Microsoft Word',
  created: 'D:20250301090000',
  modified: 'D:20250301090500',
})
const edited = makePdf({
  text: INVOICE_TEXT.replace('1440.00', '9440.00'),
  producer: 'Microsoft Word - Invoice',
  creator: 'Microsoft Word',
  created: 'D:20250301090000',
  modified: 'D:20250415221000',
  editedWith: 'iLovePDF',
})

describe('file type detection', () => {
  it('reads magic bytes before the extension', () => {
    expect(detectFileType(clean, 'renamed.docx')).toBe(PDF_TYPE)
    expect(detectFileType(Buffer.from('PK\x03\x04'), 'a.docx')).toBe(DOCX_TYPE)
    expect(detectFileType(Buffer.from('hello'), 'notes.txt')).toBeUndefined()
  })

  it('rejects unsupported files', async () => {
    await expect(analyzeDocument(Buffer.from('plain text'), { fileName: 'a.txt', ai: false })).rejects.toThrow(/PDF or DOCX/)
  })
})

describe('metadata extraction', () => {
  it('reads PDF text and Info dictionary', async () => {
    const { metadata, text } = await extractPdfMetadata(clean)
    expect(text).toContain('Total Amount Due 1440.00')
    expect(metadata.producer).toBe('Microsoft Word - Invoice')
    expect(metadata.pageCount).toBe(1)
    expect(metadata.creationDate).toMatch(/^2025-03-01T/)
  })

  it('reads DOCX text, core and app properties', async () => {
    const docx = await makeDocx({
      paragraphs: ['Service Agreement', 'The parties hereby agree to the terms and conditions below.'],
      author: 'A. Author',
      created: '2025-01-10T08:00:00Z',
      modified: '2025-01-12T10:00:00Z',
      revision: 4,
      totalTimeMinutes: 35,
    })
    const { metadata, text } = await extractDocxMetadata(docx)
    expect(text).toContain('Service Agreement')
    expect(metadata).toMatchObject({ author: 'A. Author', revisionCount: 4, pageCount: 1, totalEditTime: 35 * 60 })
  })
})

describe('PDF forensics', () => {
  it('finds no structural tampering in a single-save PDF', () => {
    const result = analyzePDFForensics({ buffer: clean, fileName: 'invoice.pdf' })
    expect(result.structureAnalysis.incrementalUpdateCount).toBe(1)
    expect(result.structureAnalysis.hasEditingMarkers).toBe(false)
  })

  it('finds an editor signature appended by an incremental update', () => {
    const result = analyzePDFForensics({ buffer: edited, fileName: 'invoice.pdf' })
    expect(result.structureAnalysis.incrementalUpdateCount).toBe(2)
    expect(result.structureAnalysis.editingMarkers).toContain('ilovepdf')
    expect(result.overallScore).toBeLessThan(analyzePDFForensics({ buffer: clean, fileName: 'invoice.pdf' }).overallScore)
  })

  it('compares an original with a suspect copy', () => {
    const result = comparePdfs(clean, edited, { original: 'original.pdf', suspect: 'suspect.pdf' })
    expect(result.suspect.eofCount).toBeGreaterThan(result.original.eofCount)
    expect(result.comparison.structuralDifferences.join(' ')).toMatch(/ilovepdf/i)
    expect(['medium', 'high', 'critical']).toContain(result.overallRisk)
  })
})

describe('full analysis', () => {
  it('produces a complete local report for a PDF invoice', async () => {
    const { report, events, compliance } = await analyzeDocument(clean, { fileName: 'invoice.pdf', ai: false })
    expect(report.analysisVersion).toMatch(/-local$/)
    expect(report.documentClassification.type.toLowerCase()).toBe('invoice')
    expect(report.authenticityAnalysis?.overallScore).toBeGreaterThan(0)
    expect(report.pdfForensicAnalysis).toBeDefined()
    expect(events.length).toBeGreaterThan(0)
    expect(compliance.grade).toMatch(/^[A-F]$/)
  })

  it('scores the edited invoice as less authentic than the original', async () => {
    const a = await analyzeDocument(clean, { fileName: 'invoice.pdf', ai: false })
    const b = await analyzeDocument(edited, { fileName: 'invoice.pdf', ai: false })
    expect(b.report.pdfForensicAnalysis!.overallScore).toBeLessThan(a.report.pdfForensicAnalysis!.overallScore)
  })

  it('analyzes a DOCX without PDF forensics', async () => {
    const docx = await makeDocx({ paragraphs: ['Dear team,', 'Please find the summary report attached.', 'Regards'] })
    const { report } = await analyzeDocument(docx, { fileName: 'letter.docx', ai: false })
    expect(report.pdfForensicAnalysis).toBeUndefined()
    expect(report.contentAnalysis.summary).toBeTruthy()
  })

  it('never calls the network when ai is false, even with a key in the environment', async () => {
    const original = globalThis.fetch
    process.env.GEMINI_API_KEY = 'env-key'
    globalThis.fetch = (() => { throw new Error('network used') }) as typeof fetch
    try {
      const { report } = await analyzeDocument(clean, { fileName: 'invoice.pdf', ai: false })
      expect(report.analysisVersion).toMatch(/-local$/)
    } finally {
      globalThis.fetch = original
      delete process.env.GEMINI_API_KEY
    }
  })

  it('sends the Gemini key in a header, not the URL', async () => {
    const original = globalThis.fetch
    let seen: { url: string; key?: string } | undefined
    globalThis.fetch = (async (url: string, init: RequestInit) => {
      seen = { url, key: (init.headers as Record<string, string>)['x-goog-api-key'] }
      return new Response('{}', { status: 500 })
    }) as typeof fetch
    try {
      await analyzeDocument(clean, { fileName: 'invoice.pdf', ai: { apiKey: 'test-key', model: 'gemini-test' } })
      expect(seen?.url).toContain('/models/gemini-test:generateContent')
      expect(seen?.url).not.toContain('test-key')
      expect(seen?.key).toBe('test-key')
    } finally {
      globalThis.fetch = original
    }
  })
})

describe('text diff', () => {
  it('measures similarity between versions', () => {
    expect(calculateSimilarity('total 1440.00', 'total 1440.00')).toBe(1)
    expect(calculateSimilarity('total 1440.00', 'total 9440.00')).toBeLessThan(1)
  })
})

describe('PDF parsing regression', () => {
  it('reads PDFs passed as pooled or offset Buffers', async () => {
    // A Buffer that is a view at a non-zero offset, like small files from fs.readFile.
    const pool = Buffer.alloc(clean.length + 64)
    clean.copy(pool, 37)
    const view = pool.subarray(37, 37 + clean.length)
    const { text, metadata } = await extractPdfMetadata(view)
    expect(text).toContain('Total Amount Due 1440.00')
    expect(metadata.producer).toBe('Microsoft Word - Invoice')
  })
})
