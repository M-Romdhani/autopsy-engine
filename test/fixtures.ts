import JSZip from 'jszip'

interface PdfOptions {
  text: string
  producer?: string
  creator?: string
  created?: string // PDF date, e.g. D:20250101120000
  modified?: string
  /** Append an incremental update that rewrites the Info dictionary, as editors do. */
  editedWith?: string
}

const escape = (s: string) => s.replace(/[\\()]/g, (c) => `\\${c}`)

/** A small, valid single-page PDF with a correct xref table. */
export function makePdf(opts: PdfOptions): Buffer {
  const lines = opts.text.split('\n')
  const stream = ['BT', '/F1 12 Tf', '72 720 Td', '14 TL', ...lines.map((l) => `(${escape(l)}) '`), 'ET'].join('\n')
  const info = [
    opts.producer && `/Producer (${escape(opts.producer)})`,
    opts.creator && `/Creator (${escape(opts.creator)})`,
    opts.created && `/CreationDate (${opts.created})`,
    opts.modified && `/ModDate (${opts.modified})`,
  ].filter(Boolean).join(' ')
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>',
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Length ${Buffer.byteLength(stream, 'latin1')} >>\nstream\n${stream}\nendstream`,
    `<< ${info} >>`,
  ]

  let body = '%PDF-1.4\n'
  const offsets: number[] = []
  objects.forEach((obj, i) => {
    offsets.push(Buffer.byteLength(body, 'latin1'))
    body += `${i + 1} 0 obj\n${obj}\nendobj\n`
  })
  const xrefAt = Buffer.byteLength(body, 'latin1')
  body += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  body += offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')
  body += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n${xrefAt}\n%%EOF\n`

  if (opts.editedWith) {
    const updAt = Buffer.byteLength(body, 'latin1')
    const updated = info.replace(/\/Producer \((?:[^()\\]|\\.)*\)/, `/Producer (${escape(opts.editedWith)})`)
    body += `6 0 obj\n<< ${updated} >>\nendobj\n`
    const xref2 = Buffer.byteLength(body, 'latin1')
    body += `xref\n0 1\n0000000000 65535 f \n6 1\n${String(updAt).padStart(10, '0')} 00000 n \n`
    body += `trailer\n<< /Size 7 /Root 1 0 R /Info 6 0 R /Prev ${xrefAt} >>\nstartxref\n${xref2}\n%%EOF\n`
  }
  return Buffer.from(body, 'latin1')
}

interface DocxOptions {
  paragraphs: string[]
  author?: string
  created?: string // ISO
  modified?: string
  revision?: number
  application?: string
  totalTimeMinutes?: number
}

/** A minimal DOCX that Word, mammoth and the engine all accept. */
export async function makeDocx(opts: DocxOptions): Promise<Buffer> {
  const zip = new JSZip()
  zip.file('[Content_Types].xml', `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>
</Types>`)
  zip.file('_rels/.rels', `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>`)
  const paras = opts.paragraphs.map((p) => `<w:p><w:r><w:t xml:space="preserve">${p}</w:t></w:r></w:p>`).join('')
  zip.file('word/document.xml', `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${paras}</w:body></w:document>`)
  zip.file('docProps/core.xml', `<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
${opts.author ? `<dc:creator>${opts.author}</dc:creator>` : ''}
${opts.created ? `<dcterms:created xsi:type="dcterms:W3CDTF">${opts.created}</dcterms:created>` : ''}
${opts.modified ? `<dcterms:modified xsi:type="dcterms:W3CDTF">${opts.modified}</dcterms:modified>` : ''}
${opts.revision !== undefined ? `<cp:revision>${opts.revision}</cp:revision>` : ''}
</cp:coreProperties>`)
  zip.file('docProps/app.xml', `<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
<Application>${opts.application ?? 'Microsoft Office Word'}</Application><Pages>1</Pages>
${opts.totalTimeMinutes !== undefined ? `<TotalTime>${opts.totalTimeMinutes}</TotalTime>` : ''}
</Properties>`)
  return zip.generateAsync({ type: 'nodebuffer' })
}

export const INVOICE_TEXT = [
  'INVOICE #2025-0142',
  'Bill To: Example Trading Ltd',
  'Description Qty Unit Price Amount',
  'Consulting services 10 120.00 1200.00',
  'Subtotal 1200.00',
  'Tax 240.00',
  'Total Amount Due 1440.00',
  'Payment due within 30 days.',
].join('\n')
