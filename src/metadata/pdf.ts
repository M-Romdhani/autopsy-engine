import type { DocumentMetadata } from '../types.js'

export async function extractPdfMetadata(buffer: Buffer): Promise<{
  metadata: DocumentMetadata
  text: string
}> {
  try {
    const pdfParse = (await import('pdf-parse/lib/pdf-parse.js')).default
    // pdf-parse's bundled pdf.js (v1.10) misreads Node Buffers, including any
    // small Buffer that is a view into Node's shared pool, and fails with
    // "bad XRef entry". A plain Uint8Array copy is read correctly.
    const data = await pdfParse(new Uint8Array(buffer) as Buffer)
    
    const text = data.text || ''
    const wordCount = text.split(/\s+/).filter(Boolean).length
    
    const metadata: DocumentMetadata = {
      title: data.info?.Title,
      author: data.info?.Author,
      subject: data.info?.Subject,
      keywords: data.info?.Keywords,
      creator: data.info?.Creator,
      producer: data.info?.Producer,
      creationDate: data.info?.CreationDate ? parsePdfDate(data.info.CreationDate) : undefined,
      modificationDate: data.info?.ModDate ? parsePdfDate(data.info.ModDate) : undefined,
      pageCount: data.numpages,
      wordCount,
    }

    return { metadata, text }
  } catch (error) {
    console.error('PDF parsing error:', error)
    return { metadata: {}, text: '' }
  }
}

function parsePdfDate(dateStr: string): string | undefined {
  try {
    if (!dateStr) return undefined
    const cleaned = dateStr.replace(/^D:/, '')
    const year = cleaned.substring(0, 4)
    const month = cleaned.substring(4, 6) || '01'
    const day = cleaned.substring(6, 8) || '01'
    const hour = cleaned.substring(8, 10) || '00'
    const minute = cleaned.substring(10, 12) || '00'
    const second = cleaned.substring(12, 14) || '00'
    const date = new Date(`${year}-${month}-${day}T${hour}:${minute}:${second}`)
    if (isNaN(date.getTime())) return undefined
    return date.toISOString()
  } catch {
    return undefined
  }
}
