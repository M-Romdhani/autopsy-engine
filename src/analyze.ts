import { generateAutopsyReport, generateMetadataEvents, type AiOptions } from './ai/inference.js'
import { calculateComplianceScore, getComplianceRecommendations, type ComplianceScore } from './compliance/score.js'
import { analyzePDFForensics, comparePDFsForensically, type ComparisonResult } from './forensics/pdfForensics.js'
import { extractDocxMetadata } from './metadata/docx.js'
import { extractPdfMetadata } from './metadata/pdf.js'
import type { AutopsyReport, DocumentMetadata, EditEvent, PDFForensicAnalysis } from './types.js'
import { generateId } from './util.js'

export const PDF_TYPE = 'application/pdf'
export const DOCX_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'

export interface AnalyzeOptions {
  fileName: string
  /** MIME type. Detected from the file's bytes when omitted. */
  fileType?: string
  /** Gemini enhancement. Omit to use GEMINI_API_KEY if set; `false` stays fully local. */
  ai?: AiOptions | false
}

export interface DocumentAnalysis {
  report: AutopsyReport
  events: EditEvent[]
  metadata: DocumentMetadata
  compliance: ComplianceScore & { recommendations: string[] }
}

/** Identify a PDF or DOCX from its bytes, falling back to the file extension. */
export function detectFileType(buffer: Buffer, fileName = ''): string | undefined {
  if (buffer.subarray(0, 5).toString('latin1') === '%PDF-') return PDF_TYPE
  if (buffer[0] === 0x50 && buffer[1] === 0x4b && /\.docx$/i.test(fileName)) return DOCX_TYPE
  if (/\.pdf$/i.test(fileName)) return PDF_TYPE
  if (/\.docx$/i.test(fileName)) return DOCX_TYPE
  return undefined
}

/**
 * Run the full autopsy on one PDF or DOCX: metadata extraction, edit-event
 * reconstruction, authenticity and content analysis, compliance scoring and,
 * for PDFs, structural forensics. Runs locally unless Gemini is configured.
 */
export async function analyzeDocument(buffer: Buffer, options: AnalyzeOptions): Promise<DocumentAnalysis> {
  const { fileName } = options
  const fileType = options.fileType ?? detectFileType(buffer, fileName)
  if (fileType !== PDF_TYPE && fileType !== DOCX_TYPE) {
    throw new Error(`Unsupported file type for ${fileName || 'document'}: use PDF or DOCX`)
  }

  const documentId = generateId()
  let pdfForensicAnalysis: PDFForensicAnalysis | undefined
  const extracted = fileType === PDF_TYPE ? await extractPdfMetadata(buffer) : await extractDocxMetadata(buffer)
  if (fileType === PDF_TYPE) {
    try {
      pdfForensicAnalysis = analyzePDFForensics({ buffer, fileName })
    } catch {
      // Structural forensics is best-effort; the rest of the report still stands.
    }
  }

  const { metadata, text: extractedText } = extracted
  const events = generateMetadataEvents(documentId, metadata, extractedText)
  const reportData = await generateAutopsyReport({
    fileName,
    fileType,
    fileSize: buffer.length,
    extractedText,
    metadata,
    events,
    buffer,
    ai: options.ai,
  })

  const report: AutopsyReport = { id: generateId(), documentId, ...reportData, pdfForensicAnalysis }
  return {
    report,
    events,
    metadata,
    compliance: { ...calculateComplianceScore(report), recommendations: getComplianceRecommendations(report) },
  }
}

/** Compare a known-good PDF with a suspect copy: size, fonts, structure and timestamps. */
export function comparePdfs(
  original: Buffer,
  suspect: Buffer,
  names: { original?: string; suspect?: string } = {},
): ComparisonResult {
  return comparePDFsForensically(original, suspect, names.original ?? 'original.pdf', names.suspect ?? 'suspect.pdf')
}
