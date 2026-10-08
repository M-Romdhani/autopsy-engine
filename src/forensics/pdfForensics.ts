/**
 * Advanced PDF Forensic Analysis Module
 *
 * Detects document tampering through multiple forensic indicators:
 * - File size anomalies
 * - Font forensics (subset detection)
 * - Timestamp analysis
 * - Link analysis (Print-to-PDF detection)
 * - PDF structure analysis
 */

export interface FontInfo {
  name: string
  isSubset: boolean
  subsetPrefix?: string
  isEmbedded: boolean
  type: 'original' | 'added' | 'unknown'
  suspicionLevel: 'none' | 'low' | 'medium' | 'high'
  reason?: string
}

export interface RedFlag {
  type: 'size_anomaly' | 'font_manipulation' | 'timestamp_mismatch' |
        'link_anomaly' | 'structure_anomaly' | 'editing_markers'
  title: string
  description: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
  technicalDetails: string
  recommendation: string
}

export interface PDFForensicResult {
  sizeAnalysis: {
    fileSize: number
    expectedSizeRange: { min: number; max: number }
    sizeAnomaly: boolean
    sizeAnomalyReason?: string
    sizeRatio?: number
    sizeScore: number
  }

  fontAnalysis: {
    fonts: FontInfo[]
    hasSubsetFonts: boolean
    hasFontMismatch: boolean
    suspiciousFonts: string[]
    originalFonts: string[]
    addedFonts: string[]
    fontScore: number
  }

  timestampAnalysis: {
    creationDate?: string
    modificationDate?: string
    creationDateRaw?: string
    modificationDateRaw?: string
    hasModificationAfterCreation: boolean
    timeDifferenceMinutes?: number
    timestampAnomaly: boolean
    timestampAnomalyReason?: string
    timestampScore: number
  }

  linkAnalysis: {
    totalLinks: number
    extractedLinks: string[]
    printToPdfIndicator: boolean
    linkScore: number
  }

  structureAnalysis: {
    pdfVersion: string
    hasIncrementalUpdates: boolean
    incrementalUpdateCount: number
    hasXrefStream: boolean
    producer?: string
    creator?: string
    hasEditingMarkers: boolean
    editingMarkers: string[]
    structureScore: number
  }

  redFlags: RedFlag[]
  overallScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  verdict: 'authentic' | 'likely_authentic' | 'suspicious' | 'likely_modified' | 'modified'
  summary: string
}

export interface ComparisonResult {
  original: {
    fileName: string
    fileSize: number
    fonts: string[]
    creationDate?: string
    modificationDate?: string
    linkCount: number
    eofCount: number
  }
  suspect: {
    fileName: string
    fileSize: number
    fonts: string[]
    creationDate?: string
    modificationDate?: string
    linkCount: number
    eofCount: number
  }
  comparison: {
    sizeRatio: number
    sizeDifference: number
    fontDifferences: {
      added: string[]
      removed: string[]
      common: string[]
    }
    timestampDifference?: string
    linkDifference: number
    structuralDifferences: string[]
  }
  overallRisk: 'low' | 'medium' | 'high' | 'critical'
  verdict: string
  recommendations: string[]
}

// Common editing tool signatures
const EDITING_TOOL_SIGNATURES = [
  'smallpdf',
  'ilovepdf',
  'pdf2go',
  'sejda',
  'pdfcandy',
  'pdfescape',
  'pdf-xchange',
  'foxit phantompdf',
  'nitro pdf',
  'pdf element',
  'pdffiller',
  'docfly',
  'pdfpro',
  'soda pdf',
  'pdf architect'
]

// Fonts commonly added during editing
const COMMON_EDITING_FONTS = [
  'arial',
  'helvetica',
  'times new roman',
  'calibri',
  'verdana',
  'tahoma',
  'georgia'
]

// Subset font prefix pattern (e.g., CVFYDU+ArialMT)
const SUBSET_FONT_PATTERN = /^[A-Z]{6}\+/

/**
 * Parse PDF date format: D:YYYYMMDDHHmmSS
 */
function parsePDFDate(dateStr: string): Date | null {
  if (!dateStr) return null

  // Remove D: prefix and timezone info
  const cleaned = dateStr.replace(/^D:/, '').replace(/[Z'+-].*$/, '')

  if (cleaned.length < 14) return null

  try {
    const year = parseInt(cleaned.substring(0, 4))
    const month = parseInt(cleaned.substring(4, 6)) - 1
    const day = parseInt(cleaned.substring(6, 8))
    const hour = parseInt(cleaned.substring(8, 10))
    const minute = parseInt(cleaned.substring(10, 12))
    const second = parseInt(cleaned.substring(12, 14))

    return new Date(year, month, day, hour, minute, second)
  } catch {
    return null
  }
}

/**
 * Extract fonts from PDF buffer
 */
function extractFonts(pdfContent: string): FontInfo[] {
  const fonts: FontInfo[] = []
  const fontSet = new Set<string>()

  // Pattern to match font names in PDF
  const fontPatterns = [
    /\/BaseFont\s*\/([^\s\/\[\]<>]+)/g,
    /\/FontName\s*\/([^\s\/\[\]<>]+)/g,
    /\/Name\s*\/([^\s\/\[\]<>]+)/g
  ]

  for (const pattern of fontPatterns) {
    let match
    while ((match = pattern.exec(pdfContent)) !== null) {
      const fontName = match[1]
      if (!fontSet.has(fontName)) {
        fontSet.add(fontName)

        const isSubset = SUBSET_FONT_PATTERN.test(fontName)
        const subsetPrefix = isSubset ? fontName.substring(0, 6) : undefined
        const baseName = isSubset ? fontName.substring(7) : fontName

        // Determine suspicion level
        let suspicionLevel: FontInfo['suspicionLevel'] = 'none'
        let reason: string | undefined

        if (isSubset) {
          // Subset fonts with common editing font names are suspicious
          const isCommonEditingFont = COMMON_EDITING_FONTS.some(
            f => baseName.toLowerCase().includes(f.toLowerCase().replace(' ', ''))
          )

          if (isCommonEditingFont) {
            suspicionLevel = 'high'
            reason = 'Subset font with common editing font name suggests document modification'
          } else {
            suspicionLevel = 'medium'
            reason = 'Subset font indicates font was embedded during editing'
          }
        }

        fonts.push({
          name: fontName,
          isSubset,
          subsetPrefix,
          isEmbedded: isSubset, // Subset fonts are always embedded
          type: 'unknown',
          suspicionLevel,
          reason
        })
      }
    }
  }

  return fonts
}

/**
 * Extract timestamps from PDF buffer
 */
function extractTimestamps(pdfContent: string): { creation?: string; modification?: string; creationRaw?: string; modificationRaw?: string } {
  let creation: string | undefined
  let modification: string | undefined
  let creationRaw: string | undefined
  let modificationRaw: string | undefined

  // Match CreationDate
  const creationMatch = pdfContent.match(/\/CreationDate\s*\(([^)]+)\)/)
  if (creationMatch) {
    creationRaw = creationMatch[1]
    const date = parsePDFDate(creationMatch[1])
    if (date) creation = date.toISOString()
  }

  // Match ModDate
  const modMatch = pdfContent.match(/\/ModDate\s*\(([^)]+)\)/)
  if (modMatch) {
    modificationRaw = modMatch[1]
    const date = parsePDFDate(modMatch[1])
    if (date) modification = date.toISOString()
  }

  return { creation, modification, creationRaw, modificationRaw }
}

/**
 * Extract links/URIs from PDF buffer
 */
function extractLinks(pdfContent: string): string[] {
  const links: string[] = []
  const linkSet = new Set<string>()

  // Match URI patterns
  const uriPattern = /\/URI\s*\(([^)]+)\)/g
  let match
  while ((match = uriPattern.exec(pdfContent)) !== null) {
    if (!linkSet.has(match[1])) {
      linkSet.add(match[1])
      links.push(match[1])
    }
  }

  // Also check for /A actions with URIs
  const actionPattern = /\/S\s*\/URI\s*\/URI\s*\(([^)]+)\)/g
  while ((match = actionPattern.exec(pdfContent)) !== null) {
    if (!linkSet.has(match[1])) {
      linkSet.add(match[1])
      links.push(match[1])
    }
  }

  return links
}

/**
 * Analyze PDF structure
 */
function analyzeStructure(pdfContent: string): {
  version: string
  eofCount: number
  hasXrefStream: boolean
  producer?: string
  creator?: string
  editingMarkers: string[]
} {
  // Extract PDF version
  const versionMatch = pdfContent.match(/%PDF-(\d+\.\d+)/)
  const version = versionMatch ? versionMatch[1] : 'unknown'

  // Count EOF markers (multiple = incremental updates)
  const eofMatches = pdfContent.match(/%%EOF/g)
  const eofCount = eofMatches ? eofMatches.length : 0

  // Check for xref streams
  const hasXrefStream = /\/Type\s*\/XRef/.test(pdfContent)

  // Producer and creator. An editor saving incrementally appends a new Info
  // dictionary, so the last occurrence is the current one and every occurrence
  // is evidence of a tool that touched the file.
  const producers = [...pdfContent.matchAll(/\/Producer\s*\(([^)]+)\)/g)].map((m) => m[1])
  const creators = [...pdfContent.matchAll(/\/Creator\s*\(([^)]+)\)/g)].map((m) => m[1])
  const producer = producers.at(-1)
  const creator = creators.at(-1)

  // Check for editing tool signatures
  const editingMarkers: string[] = []
  const combinedMeta = [...producers, ...creators].join(' ').toLowerCase()

  for (const tool of EDITING_TOOL_SIGNATURES) {
    if (combinedMeta.includes(tool.toLowerCase())) {
      editingMarkers.push(tool)
    }
  }

  return { version, eofCount, hasXrefStream, producer, creator, editingMarkers }
}

/**
 * Main PDF forensic analysis function
 */
export function analyzePDFForensics(params: {
  buffer: Buffer
  fileName: string
  referenceSize?: number
  referenceFonts?: string[]
}): PDFForensicResult {
  const { buffer, fileName, referenceSize, referenceFonts } = params
  const redFlags: RedFlag[] = []

  // Convert buffer to string for text-based analysis
  const pdfContent = buffer.toString('latin1')

  // 1. SIZE ANALYSIS
  const fileSize = buffer.length
  const expectedMin = referenceSize ? referenceSize * 0.8 : fileSize * 0.5
  const expectedMax = referenceSize ? referenceSize * 1.5 : fileSize * 1.5
  const sizeAnomaly = referenceSize ? (fileSize > referenceSize * 2 || fileSize < referenceSize * 0.3) : false
  const sizeRatio = referenceSize ? fileSize / referenceSize : undefined

  let sizeScore = 100
  let sizeAnomalyReason: string | undefined

  if (sizeAnomaly && sizeRatio) {
    if (sizeRatio > 2) {
      sizeScore = 30
      sizeAnomalyReason = `File is ${sizeRatio.toFixed(1)}x larger than reference (common for edited documents)`
      redFlags.push({
        type: 'size_anomaly',
        title: 'Abnormal File Size',
        description: `Document is ${sizeRatio.toFixed(1)}x larger than expected`,
        severity: sizeRatio > 3 ? 'high' : 'medium',
        confidence: 0.85,
        technicalDetails: `File size: ${fileSize} bytes, Expected: ~${referenceSize} bytes`,
        recommendation: 'Compare with original document to verify integrity'
      })
    } else if (sizeRatio < 0.3) {
      sizeScore = 50
      sizeAnomalyReason = `File is unusually small (${(sizeRatio * 100).toFixed(0)}% of reference)`
    }
  }

  // 2. FONT ANALYSIS
  const fonts = extractFonts(pdfContent)
  const subsetFonts = fonts.filter(f => f.isSubset)
  const suspiciousFonts = fonts.filter(f => f.suspicionLevel === 'high' || f.suspicionLevel === 'medium')

  let fontScore = 100
  const hasSubsetFonts = subsetFonts.length > 0
  let hasFontMismatch = false
  const addedFonts: string[] = []
  const originalFonts: string[] = referenceFonts || []

  if (referenceFonts && referenceFonts.length > 0) {
    const currentFontNames = fonts.map(f => f.name)
    for (const font of currentFontNames) {
      if (!referenceFonts.includes(font)) {
        addedFonts.push(font)
        hasFontMismatch = true
      }
    }

    if (addedFonts.length > 0) {
      fontScore -= addedFonts.length * 15
      redFlags.push({
        type: 'font_manipulation',
        title: 'New Fonts Detected',
        description: `${addedFonts.length} font(s) not present in original document`,
        severity: addedFonts.length > 2 ? 'high' : 'medium',
        confidence: 0.9,
        technicalDetails: `Added fonts: ${addedFonts.join(', ')}`,
        recommendation: 'Fonts added during editing indicate document modification'
      })
    }
  }

  // Check for suspicious subset fonts
  if (suspiciousFonts.length > 0) {
    fontScore -= suspiciousFonts.length * 10
    redFlags.push({
      type: 'font_manipulation',
      title: 'Subset Fonts Detected',
      description: `${suspiciousFonts.length} subset font(s) found (indicates editing)`,
      severity: suspiciousFonts.some(f => f.suspicionLevel === 'high') ? 'high' : 'medium',
      confidence: 0.85,
      technicalDetails: suspiciousFonts.map(f => `${f.name}: ${f.reason}`).join('; '),
      recommendation: 'Subset fonts with 6-letter prefixes indicate font embedding during document modification'
    })
  }

  fontScore = Math.max(0, fontScore)

  // 3. TIMESTAMP ANALYSIS
  const timestamps = extractTimestamps(pdfContent)
  let timestampScore = 100
  let hasModificationAfterCreation = false
  let timeDifferenceMinutes: number | undefined
  let timestampAnomaly = false
  let timestampAnomalyReason: string | undefined

  if (timestamps.creation && timestamps.modification) {
    const creation = new Date(timestamps.creation)
    const modification = new Date(timestamps.modification)
    timeDifferenceMinutes = (modification.getTime() - creation.getTime()) / (1000 * 60)

    if (timeDifferenceMinutes > 5) { // More than 5 minutes difference
      hasModificationAfterCreation = true
      timestampAnomaly = true
      timestampScore = timeDifferenceMinutes > 60 ? 40 : 70
      timestampAnomalyReason = `Modified ${Math.round(timeDifferenceMinutes)} minutes after creation`

      redFlags.push({
        type: 'timestamp_mismatch',
        title: 'Document Modified After Creation',
        description: `Document was modified ${timeDifferenceMinutes > 60 ? Math.round(timeDifferenceMinutes / 60) + ' hours' : Math.round(timeDifferenceMinutes) + ' minutes'} after creation`,
        severity: timeDifferenceMinutes > 60 ? 'high' : 'medium',
        confidence: 0.95,
        technicalDetails: `Created: ${timestamps.creation}, Modified: ${timestamps.modification}`,
        recommendation: 'For financial documents like invoices, modification after creation is unusual'
      })
    }
  } else if (!timestamps.creation) {
    timestampScore = 60
    timestampAnomaly = true
    timestampAnomalyReason = 'Missing creation date (may have been stripped)'
  }

  // 4. LINK ANALYSIS
  const extractedLinks = extractLinks(pdfContent)
  const totalLinks = extractedLinks.length
  let linkScore = 100
  let printToPdfIndicator = false

  // Financial documents with zero links might indicate Print-to-PDF
  const isFinancialDoc = /invoice|receipt|statement|bill/i.test(fileName)
  if (isFinancialDoc && totalLinks === 0) {
    printToPdfIndicator = true
    linkScore = 70
    redFlags.push({
      type: 'link_anomaly',
      title: 'No Clickable Links Found',
      description: 'Financial document contains no links (Print-to-PDF indicator)',
      severity: 'medium',
      confidence: 0.7,
      technicalDetails: 'Documents exported directly from accounting software typically contain clickable links',
      recommendation: 'Compare with known authentic documents from the same source'
    })
  }

  // 5. STRUCTURE ANALYSIS
  const structure = analyzeStructure(pdfContent)
  let structureScore = 100

  // Multiple EOF markers indicate incremental saves (edits)
  if (structure.eofCount > 1) {
    structureScore -= (structure.eofCount - 1) * 15
    redFlags.push({
      type: 'structure_anomaly',
      title: 'Multiple Save Operations Detected',
      description: `Document was saved ${structure.eofCount} times (incremental updates)`,
      severity: structure.eofCount > 3 ? 'high' : 'medium',
      confidence: 0.9,
      technicalDetails: `Found ${structure.eofCount} %%EOF markers in PDF structure`,
      recommendation: 'Multiple saves indicate the document was opened and modified multiple times'
    })
  }

  // Editing tool signatures
  if (structure.editingMarkers.length > 0) {
    structureScore -= 25
    redFlags.push({
      type: 'editing_markers',
      title: 'PDF Editing Tool Detected',
      description: `Document shows signs of being edited with: ${structure.editingMarkers.join(', ')}`,
      severity: 'high',
      confidence: 0.95,
      technicalDetails: `Producer: ${structure.producer || 'N/A'}, Creator: ${structure.creator || 'N/A'}`,
      recommendation: 'PDF editing tools are commonly used to modify document content'
    })
  }

  structureScore = Math.max(0, structureScore)

  // CALCULATE OVERALL SCORE
  const weights = {
    size: 0.15,
    font: 0.25,
    timestamp: 0.25,
    link: 0.15,
    structure: 0.20
  }

  const overallScore = Math.round(
    sizeScore * weights.size +
    fontScore * weights.font +
    timestampScore * weights.timestamp +
    linkScore * weights.link +
    structureScore * weights.structure
  )

  // Determine risk level and verdict
  let riskLevel: PDFForensicResult['riskLevel']
  let verdict: PDFForensicResult['verdict']

  if (overallScore >= 85) {
    riskLevel = 'low'
    verdict = 'authentic'
  } else if (overallScore >= 70) {
    riskLevel = 'medium'
    verdict = 'likely_authentic'
  } else if (overallScore >= 50) {
    riskLevel = 'high'
    verdict = 'suspicious'
  } else if (overallScore >= 30) {
    riskLevel = 'high'
    verdict = 'likely_modified'
  } else {
    riskLevel = 'critical'
    verdict = 'modified'
  }

  // Generate summary
  let summary = ''
  if (verdict === 'authentic' || verdict === 'likely_authentic') {
    summary = `PDF forensic analysis indicates this document is ${verdict === 'authentic' ? 'authentic' : 'likely authentic'} with a score of ${overallScore}%. No significant tampering indicators were found.`
  } else if (verdict === 'suspicious') {
    summary = `PDF forensic analysis detected ${redFlags.length} potential issue(s) with a score of ${overallScore}%. Manual verification is recommended.`
  } else {
    summary = `WARNING: PDF forensic analysis indicates this document has likely been modified. Score: ${overallScore}%. ${redFlags.length} red flag(s) detected including: ${redFlags.slice(0, 2).map(f => f.title).join(', ')}.`
  }

  return {
    sizeAnalysis: {
      fileSize,
      expectedSizeRange: { min: expectedMin, max: expectedMax },
      sizeAnomaly,
      sizeAnomalyReason,
      sizeRatio,
      sizeScore
    },
    fontAnalysis: {
      fonts,
      hasSubsetFonts,
      hasFontMismatch,
      suspiciousFonts: suspiciousFonts.map(f => f.name),
      originalFonts,
      addedFonts,
      fontScore
    },
    timestampAnalysis: {
      creationDate: timestamps.creation,
      modificationDate: timestamps.modification,
      creationDateRaw: timestamps.creationRaw,
      modificationDateRaw: timestamps.modificationRaw,
      hasModificationAfterCreation,
      timeDifferenceMinutes,
      timestampAnomaly,
      timestampAnomalyReason,
      timestampScore
    },
    linkAnalysis: {
      totalLinks,
      extractedLinks,
      printToPdfIndicator,
      linkScore
    },
    structureAnalysis: {
      pdfVersion: structure.version,
      hasIncrementalUpdates: structure.eofCount > 1,
      incrementalUpdateCount: structure.eofCount,
      hasXrefStream: structure.hasXrefStream,
      producer: structure.producer,
      creator: structure.creator,
      hasEditingMarkers: structure.editingMarkers.length > 0,
      editingMarkers: structure.editingMarkers,
      structureScore
    },
    redFlags,
    overallScore,
    riskLevel,
    verdict,
    summary
  }
}

/**
 * Compare two PDFs forensically
 */
export function comparePDFsForensically(
  originalBuffer: Buffer,
  suspectBuffer: Buffer,
  originalFileName: string,
  suspectFileName: string
): ComparisonResult {
  // Analyze both documents
  const originalAnalysis = analyzePDFForensics({
    buffer: originalBuffer,
    fileName: originalFileName
  })

  const suspectAnalysis = analyzePDFForensics({
    buffer: suspectBuffer,
    fileName: suspectFileName,
    referenceSize: originalBuffer.length,
    referenceFonts: originalAnalysis.fontAnalysis.fonts.map(f => f.name)
  })

  // Calculate differences
  const sizeRatio = suspectBuffer.length / originalBuffer.length
  const sizeDifference = suspectBuffer.length - originalBuffer.length

  const originalFontNames = new Set(originalAnalysis.fontAnalysis.fonts.map(f => f.name))
  const suspectFontNames = new Set(suspectAnalysis.fontAnalysis.fonts.map(f => f.name))

  const addedFonts = [...suspectFontNames].filter(f => !originalFontNames.has(f))
  const removedFonts = [...originalFontNames].filter(f => !suspectFontNames.has(f))
  const commonFonts = [...originalFontNames].filter(f => suspectFontNames.has(f))

  // Timestamp difference
  let timestampDifference: string | undefined
  if (originalAnalysis.timestampAnalysis.creationDate && suspectAnalysis.timestampAnalysis.creationDate) {
    const origDate = new Date(originalAnalysis.timestampAnalysis.creationDate)
    const suspDate = new Date(suspectAnalysis.timestampAnalysis.creationDate)
    const diffMs = Math.abs(suspDate.getTime() - origDate.getTime())
    const diffHours = diffMs / (1000 * 60 * 60)
    timestampDifference = diffHours > 24
      ? `${Math.round(diffHours / 24)} days`
      : `${Math.round(diffHours)} hours`
  }

  // Link difference
  const linkDifference = suspectAnalysis.linkAnalysis.totalLinks - originalAnalysis.linkAnalysis.totalLinks

  // Structural differences
  const structuralDifferences: string[] = []
  if (suspectAnalysis.structureAnalysis.incrementalUpdateCount > originalAnalysis.structureAnalysis.incrementalUpdateCount) {
    structuralDifferences.push(`Additional saves: ${suspectAnalysis.structureAnalysis.incrementalUpdateCount - originalAnalysis.structureAnalysis.incrementalUpdateCount}`)
  }
  if (suspectAnalysis.structureAnalysis.hasEditingMarkers && !originalAnalysis.structureAnalysis.hasEditingMarkers) {
    structuralDifferences.push(`Editing markers added: ${suspectAnalysis.structureAnalysis.editingMarkers.join(', ')}`)
  }

  // Determine overall risk
  let overallRisk: ComparisonResult['overallRisk'] = 'low'
  const riskFactors: string[] = []

  if (sizeRatio > 2) {
    overallRisk = 'high'
    riskFactors.push('significant size increase')
  }
  if (addedFonts.length > 0) {
    overallRisk = overallRisk === 'low' ? 'medium' : 'high'
    riskFactors.push('new fonts added')
  }
  if (structuralDifferences.length > 0) {
    overallRisk = overallRisk === 'low' ? 'medium' : overallRisk
    riskFactors.push('structural changes')
  }
  if (suspectAnalysis.structureAnalysis.hasEditingMarkers) {
    overallRisk = 'critical'
    riskFactors.push('editing tool signatures')
  }

  // Generate verdict
  let verdict: string
  if (overallRisk === 'critical') {
    verdict = 'Document has been modified with PDF editing tools'
  } else if (overallRisk === 'high') {
    verdict = 'Document shows significant signs of modification'
  } else if (overallRisk === 'medium') {
    verdict = 'Document shows minor differences from original'
  } else {
    verdict = 'Documents appear to be identical or minimally different'
  }

  // Generate recommendations
  const recommendations: string[] = []
  if (addedFonts.length > 0) {
    recommendations.push(`Investigate added fonts: ${addedFonts.join(', ')}`)
  }
  if (sizeRatio > 1.5) {
    recommendations.push('Significant size increase indicates embedded content changes')
  }
  if (suspectAnalysis.structureAnalysis.hasEditingMarkers) {
    recommendations.push('Request original document from source')
  }
  recommendations.push('Compare document content visually for specific changes')

  return {
    original: {
      fileName: originalFileName,
      fileSize: originalBuffer.length,
      fonts: [...originalFontNames],
      creationDate: originalAnalysis.timestampAnalysis.creationDate,
      modificationDate: originalAnalysis.timestampAnalysis.modificationDate,
      linkCount: originalAnalysis.linkAnalysis.totalLinks,
      eofCount: originalAnalysis.structureAnalysis.incrementalUpdateCount
    },
    suspect: {
      fileName: suspectFileName,
      fileSize: suspectBuffer.length,
      fonts: [...suspectFontNames],
      creationDate: suspectAnalysis.timestampAnalysis.creationDate,
      modificationDate: suspectAnalysis.timestampAnalysis.modificationDate,
      linkCount: suspectAnalysis.linkAnalysis.totalLinks,
      eofCount: suspectAnalysis.structureAnalysis.incrementalUpdateCount
    },
    comparison: {
      sizeRatio,
      sizeDifference,
      fontDifferences: {
        added: addedFonts,
        removed: removedFonts,
        common: commonFonts
      },
      timestampDifference,
      linkDifference,
      structuralDifferences
    },
    overallRisk,
    verdict,
    recommendations
  }
}
