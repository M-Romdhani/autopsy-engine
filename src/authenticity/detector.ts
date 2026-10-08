import { DocumentMetadata, EditEvent, AuthenticityAnalysis } from '../types.js'

export interface DetectionContext {
  metadata?: DocumentMetadata
  text: string
  fileName: string
  fileType: string
  fileSize: number
  events?: EditEvent[]
}

export interface MetadataAnalysisResult {
  score: number
  creationDateValid: boolean
  modificationDateValid: boolean
  authorConsistent: boolean
  softwareSignatureValid: boolean
  timestampSequenceValid: boolean
  anomalies: Array<{
    field: string
    issue: string
    severity: 'low' | 'medium' | 'high'
  }>
}

export interface ContentAnalysisResult {
  score: number
  textConsistencyScore: number
  formatConsistencyScore: number
  contentCoherenceScore: number
  issues: Array<{
    type: string
    location: string
    description: string
    severity: 'low' | 'medium' | 'high'
  }>
}

// Common patterns found in fraudulent documents
const SUSPICIOUS_PATTERNS = {
  // Suspicious software signatures often used for forgery
  suspiciousSoftware: [
    'online pdf editor',
    'smallpdf',
    'ilovepdf',
    'pdf2go',
    'sejda',
    'pdfcandy',
    'combinepdf',
  ],

  // Legitimate software signatures
  legitimateSoftware: [
    'microsoft word',
    'microsoft office',
    'adobe acrobat',
    'adobe indesign',
    'libreoffice',
    'google docs',
    'apple pages',
    'quickbooks',
    'sage',
    'xero',
    'freshbooks',
  ],

  // Common phrases in fake financial documents
  suspiciousFinancialPhrases: [
    'wire transfer immediately',
    'urgent payment required',
    'account suspended',
    'verify your account',
    'click here to confirm',
  ],

  // Valid currency symbols
  currencySymbols: ['$', '€', '£', '¥', '₹', '₽', 'CHF', 'AUD', 'CAD', 'USD', 'EUR', 'GBP'],
}

// Analyze metadata for signs of tampering
export function analyzeMetadataAuthenticity(context: DetectionContext): MetadataAnalysisResult {
  const { metadata, fileName } = context
  const anomalies: MetadataAnalysisResult['anomalies'] = []
  let score = 100

  if (!metadata) {
    return {
      score: 50,
      creationDateValid: false,
      modificationDateValid: false,
      authorConsistent: false,
      softwareSignatureValid: false,
      timestampSequenceValid: false,
      anomalies: [{
        field: 'metadata',
        issue: 'No metadata available - could indicate stripped or modified document',
        severity: 'medium'
      }]
    }
  }

  // Check creation date validity
  let creationDateValid = true
  if (metadata.creationDate) {
    const creationDate = new Date(metadata.creationDate)
    const now = new Date()

    // Future date check
    if (creationDate > now) {
      creationDateValid = false
      score -= 25
      anomalies.push({
        field: 'creationDate',
        issue: 'Creation date is in the future - likely tampered',
        severity: 'high'
      })
    }

    // Very old date check (before 1990 for digital docs)
    if (creationDate.getFullYear() < 1990) {
      creationDateValid = false
      score -= 15
      anomalies.push({
        field: 'creationDate',
        issue: 'Creation date predates common digital document formats',
        severity: 'medium'
      })
    }
  } else {
    creationDateValid = false
    score -= 10
    anomalies.push({
      field: 'creationDate',
      issue: 'Missing creation date - may indicate metadata was stripped',
      severity: 'low'
    })
  }

  // Check modification date validity
  let modificationDateValid = true
  if (metadata.modificationDate) {
    const modDate = new Date(metadata.modificationDate)
    const now = new Date()

    if (modDate > now) {
      modificationDateValid = false
      score -= 20
      anomalies.push({
        field: 'modificationDate',
        issue: 'Modification date is in the future',
        severity: 'high'
      })
    }
  }

  // Check timestamp sequence (modification should be after creation)
  let timestampSequenceValid = true
  if (metadata.creationDate && metadata.modificationDate) {
    const creation = new Date(metadata.creationDate)
    const modification = new Date(metadata.modificationDate)

    if (modification < creation) {
      timestampSequenceValid = false
      score -= 25
      anomalies.push({
        field: 'timestamps',
        issue: 'Modification date is before creation date - strong indicator of tampering',
        severity: 'high'
      })
    }
  }

  // Check software signature
  let softwareSignatureValid = true
  const producer = (metadata.producer || '').toLowerCase()
  const creator = (metadata.creator || '').toLowerCase()
  const software = producer + ' ' + creator

  for (const suspicious of SUSPICIOUS_PATTERNS.suspiciousSoftware) {
    if (software.includes(suspicious)) {
      softwareSignatureValid = false
      score -= 15
      anomalies.push({
        field: 'software',
        issue: `Document edited with online PDF editor (${suspicious}) - commonly used for document modification`,
        severity: 'medium'
      })
      break
    }
  }

  // Check author consistency
  let authorConsistent = true
  if (metadata.author) {
    // Check if author looks like a valid name
    const author = metadata.author

    // Check for placeholder or generic names
    if (['user', 'admin', 'test', 'unknown', 'owner'].includes(author.toLowerCase())) {
      authorConsistent = false
      score -= 5
      anomalies.push({
        field: 'author',
        issue: 'Generic or placeholder author name detected',
        severity: 'low'
      })
    }

    // Check if author matches filename pattern (suspicious)
    if (fileName.toLowerCase().includes('invoice') || fileName.toLowerCase().includes('bill')) {
      // For financial documents, author should be a company name or person
      if (author.length < 2) {
        authorConsistent = false
        score -= 10
        anomalies.push({
          field: 'author',
          issue: 'Very short author name for financial document',
          severity: 'medium'
        })
      }
    }
  }

  // Check for excessive revisions (might indicate heavy editing)
  if (metadata.revisionCount && metadata.revisionCount > 50) {
    score -= 10
    anomalies.push({
      field: 'revisionCount',
      issue: `High number of revisions (${metadata.revisionCount}) - may indicate extensive modification`,
      severity: 'low'
    })
  }

  return {
    score: Math.max(0, score),
    creationDateValid,
    modificationDateValid,
    authorConsistent,
    softwareSignatureValid,
    timestampSequenceValid,
    anomalies
  }
}

// Analyze content for signs of manipulation
export function analyzeContentAuthenticity(context: DetectionContext): ContentAnalysisResult {
  const { text, fileName } = context
  const issues: ContentAnalysisResult['issues'] = []
  let textConsistencyScore = 100
  let formatConsistencyScore = 100
  let contentCoherenceScore = 100

  if (!text || text.length < 10) {
    return {
      score: 50,
      textConsistencyScore: 50,
      formatConsistencyScore: 50,
      contentCoherenceScore: 50,
      issues: [{
        type: 'content',
        location: 'document',
        description: 'Very little or no text content to analyze',
        severity: 'medium'
      }]
    }
  }

  // Check for mixed date formats
  const dateFormats = detectDateFormats(text)
  if (dateFormats.mixed) {
    formatConsistencyScore -= 20
    issues.push({
      type: 'format_inconsistency',
      location: 'dates',
      description: `Mixed date formats detected (${dateFormats.formats.join(', ')}) - suggests content from multiple sources`,
      severity: 'medium'
    })
  }

  // Check for suspicious amount patterns in financial documents
  if (isFinancialDocument(fileName, text)) {
    const amountAnalysis = analyzeAmounts(text)
    if (amountAnalysis.suspicious) {
      contentCoherenceScore -= 15
      for (const issue of amountAnalysis.issues) {
        issues.push({
          type: 'amount_anomaly',
          location: 'amounts',
          description: issue,
          severity: 'medium'
        })
      }
    }

    // Check for mixed currency symbols
    const currencies = detectCurrencies(text)
    if (currencies.length > 1) {
      formatConsistencyScore -= 15
      issues.push({
        type: 'currency_inconsistency',
        location: 'amounts',
        description: `Multiple currencies detected (${currencies.join(', ')}) - unusual for a single document`,
        severity: 'medium'
      })
    }
  }

  // Check for copy-paste indicators
  const copyPasteIndicators = detectCopyPaste(text)
  if (copyPasteIndicators.detected) {
    textConsistencyScore -= 20
    for (const indicator of copyPasteIndicators.indicators) {
      issues.push({
        type: 'copy_paste',
        location: indicator.location,
        description: indicator.description,
        severity: indicator.severity
      })
    }
  }

  // Check for suspicious phrases
  for (const phrase of SUSPICIOUS_PATTERNS.suspiciousFinancialPhrases) {
    if (text.toLowerCase().includes(phrase)) {
      contentCoherenceScore -= 15
      issues.push({
        type: 'suspicious_phrase',
        location: 'content',
        description: `Suspicious phrase detected: "${phrase}" - commonly used in phishing/scam documents`,
        severity: 'high'
      })
    }
  }

  // Check for inconsistent capitalization patterns
  const capsIssues = detectCapitalizationIssues(text)
  if (capsIssues.length > 0) {
    textConsistencyScore -= 10
    for (const issue of capsIssues) {
      issues.push({
        type: 'capitalization',
        location: 'text',
        description: issue,
        severity: 'low'
      })
    }
  }

  const averageScore = (textConsistencyScore + formatConsistencyScore + contentCoherenceScore) / 3

  return {
    score: Math.max(0, averageScore),
    textConsistencyScore: Math.max(0, textConsistencyScore),
    formatConsistencyScore: Math.max(0, formatConsistencyScore),
    contentCoherenceScore: Math.max(0, contentCoherenceScore),
    issues
  }
}

// Detect financial document characteristics
export function analyzeFinancialDocument(context: DetectionContext): AuthenticityAnalysis['financialDocumentChecks'] {
  const { text, fileName } = context

  const isFinancial = isFinancialDocument(fileName, text)
  if (!isFinancial) {
    return undefined
  }

  const documentType = detectFinancialDocumentType(fileName, text)
  const lowerText = text.toLowerCase()

  // Currency detection and consistency check
  const currencies = detectCurrencies(text)
  const currencyConsistent = currencies.length <= 1

  // Date format detection and consistency
  const dateFormats = detectDateFormats(text)
  const dateFormatsConsistent = !dateFormats.mixed

  // Amount analysis
  const amountAnalysis = analyzeAmountsInDetail(text)

  // Logo/company indicators
  const hasLogoIndicators = /\b(logo|trademark|®|©|™)\b/i.test(text) ||
    /\b(company|corporation|inc\.|ltd\.|llc|plc|gmbh|sarl)\b/i.test(text)

  // Reference number validation
  const referencePatterns = [
    /invoice\s*(number|#|no\.?|num)\s*:?\s*[\w\-]+/i,
    /order\s*(number|#|no\.?|num)\s*:?\s*[\w\-]+/i,
    /ref(erence)?\s*(number|#|no\.?|num)?\s*:?\s*[\w\-]+/i,
    /transaction\s*(id|#|no\.?)\s*:?\s*[\w\-]+/i,
    /account\s*(number|#|no\.?)\s*:?\s*[\w\-]+/i
  ]
  const hasReferenceNumbers = referencePatterns.some(pattern => pattern.test(text))

  // Check for suspicious amounts
  const suspiciousAmounts: Array<{ amount: string; reason: string }> = []

  // Round number check
  const amounts = text.match(/\$[\d,]+\.?\d*/g) || []
  const numericAmounts = amounts.map(a => ({
    original: a,
    value: parseFloat(a.replace(/[$,]/g, ''))
  }))

  for (const amt of numericAmounts) {
    if (amt.value > 1000 && amt.value % 1000 === 0) {
      suspiciousAmounts.push({
        amount: amt.original,
        reason: 'Suspiciously round number (exact thousands)'
      })
    }
  }

  // Check for duplicate amounts that shouldn't be duplicated
  const amountCounts = new Map<number, number>()
  numericAmounts.forEach(a => {
    amountCounts.set(a.value, (amountCounts.get(a.value) || 0) + 1)
  })

  // More than 4 identical amounts is suspicious (except for common values like 0.00)
  for (const [value, count] of amountCounts) {
    if (count > 4 && value > 0) {
      suspiciousAmounts.push({
        amount: `$${value.toFixed(2)}`,
        reason: `Same amount appears ${count} times`
      })
    }
  }

  // Verify amounts add up (if we can identify subtotal/total pattern)
  const totalsValid = verifyTotals(text, numericAmounts)

  return {
    isFinancialDocument: true,
    documentType,
    currencyConsistent,
    amountsValid: suspiciousAmounts.length === 0 && totalsValid,
    dateFormatsConsistent,
    logoPresent: hasLogoIndicators,
    referenceNumbersValid: hasReferenceNumbers,
    suspiciousAmounts
  }
}

function analyzeAmountsInDetail(text: string): {
  amounts: number[]
  hasSubtotal: boolean
  hasTotal: boolean
  hasTax: boolean
  calculationsMatch: boolean
} {
  const amounts = text.match(/\$[\d,]+\.?\d*/g) || []
  const numericAmounts = amounts.map(a => parseFloat(a.replace(/[$,]/g, '')))

  const hasSubtotal = /subtotal/i.test(text)
  const hasTotal = /\btotal\b/i.test(text)
  const hasTax = /\b(tax|vat|gst)\b/i.test(text)

  // Try to verify calculations
  let calculationsMatch = true
  if (numericAmounts.length > 2 && hasTotal) {
    const sorted = [...numericAmounts].sort((a, b) => b - a)
    const largest = sorted[0]
    const sumOfSmaller = sorted.slice(1).reduce((a, b) => a + b, 0)

    // Allow 15% tolerance for rounding/tax
    if (largest > 0 && Math.abs(largest - sumOfSmaller) / largest > 0.15) {
      calculationsMatch = false
    }
  }

  return {
    amounts: numericAmounts,
    hasSubtotal,
    hasTotal,
    hasTax,
    calculationsMatch
  }
}

function verifyTotals(text: string, amounts: Array<{ original: string; value: number }>): boolean {
  if (amounts.length < 2) return true

  // Look for subtotal -> total pattern
  const subtotalMatch = text.match(/subtotal[:\s]*\$?([\d,]+\.?\d*)/i)
  const totalMatch = text.match(/\btotal[:\s]*\$?([\d,]+\.?\d*)/i)

  if (subtotalMatch && totalMatch) {
    const subtotal = parseFloat(subtotalMatch[1].replace(/,/g, ''))
    const total = parseFloat(totalMatch[1].replace(/,/g, ''))

    // Total should be >= subtotal (with tax) but not more than 50% higher
    if (total < subtotal || total > subtotal * 1.5) {
      return false
    }
  }

  return true
}

// Helper function to detect date formats
function detectDateFormats(text: string): { mixed: boolean; formats: string[] } {
  const formats: string[] = []

  // MM/DD/YYYY
  if (/\b\d{1,2}\/\d{1,2}\/\d{4}\b/.test(text)) formats.push('MM/DD/YYYY')
  // DD/MM/YYYY
  if (/\b\d{1,2}\/\d{1,2}\/\d{4}\b/.test(text) && formats.length === 0) formats.push('DD/MM/YYYY')
  // YYYY-MM-DD
  if (/\b\d{4}-\d{2}-\d{2}\b/.test(text)) formats.push('YYYY-MM-DD')
  // Month DD, YYYY
  if (/\b(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/i.test(text)) formats.push('Month DD, YYYY')
  // DD Month YYYY
  if (/\b\d{1,2}\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b/i.test(text)) formats.push('DD Month YYYY')

  return {
    mixed: formats.length > 1,
    formats
  }
}

// Helper function to detect currencies
function detectCurrencies(text: string): string[] {
  const found: string[] = []

  if (/\$\d/.test(text)) found.push('USD/Generic $')
  if (/€\d/.test(text)) found.push('EUR')
  if (/£\d/.test(text)) found.push('GBP')
  if (/¥\d/.test(text)) found.push('JPY/CNY')
  if (/₹\d/.test(text)) found.push('INR')
  if (/\bUSD\b/.test(text) && !found.includes('USD/Generic $')) found.push('USD')
  if (/\bEUR\b/.test(text) && !found.includes('EUR')) found.push('EUR')
  if (/\bGBP\b/.test(text) && !found.includes('GBP')) found.push('GBP')

  return found
}

// Helper function to analyze amounts
function analyzeAmounts(text: string): {
  suspicious: boolean
  issues: string[]
  suspiciousAmounts: Array<{ amount: string; reason: string }>
} {
  const issues: string[] = []
  const suspiciousAmounts: Array<{ amount: string; reason: string }> = []

  // Extract all amounts
  const amountPattern = /[$€£¥₹]?\s*\d{1,3}(?:[,.\s]\d{3})*(?:[.,]\d{2})?\b/g
  const amounts = text.match(amountPattern) || []

  // Check for round numbers (often fake)
  const roundNumbers = amounts.filter(a => {
    const num = parseFloat(a.replace(/[^0-9.]/g, ''))
    return num > 100 && num % 100 === 0
  })

  if (roundNumbers.length > amounts.length * 0.7 && amounts.length > 3) {
    issues.push('Unusually high proportion of round numbers - may indicate fabricated amounts')
    roundNumbers.slice(0, 3).forEach(amount => {
      suspiciousAmounts.push({
        amount,
        reason: 'Suspiciously round number'
      })
    })
  }

  // Check for amounts that don't add up (basic check)
  // This is a simplified check - a real implementation would be more sophisticated

  return {
    suspicious: issues.length > 0,
    issues,
    suspiciousAmounts
  }
}

// Helper function to detect copy-paste indicators
function detectCopyPaste(text: string): {
  detected: boolean
  indicators: Array<{ location: string; description: string; severity: 'low' | 'medium' | 'high' }>
} {
  const indicators: Array<{ location: string; description: string; severity: 'low' | 'medium' | 'high' }> = []

  // Check for repeated paragraphs
  const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 50)
  const seen = new Set<string>()

  for (const p of paragraphs) {
    const normalized = p.trim().toLowerCase()
    if (seen.has(normalized)) {
      indicators.push({
        location: 'paragraph',
        description: 'Duplicate paragraph detected - possible copy-paste',
        severity: 'medium'
      })
    }
    seen.add(normalized)
  }

  // Check for unusual whitespace patterns (often from copy-paste)
  if (/\s{4,}/.test(text) && !/\t/.test(text)) {
    indicators.push({
      location: 'whitespace',
      description: 'Unusual whitespace patterns detected',
      severity: 'low'
    })
  }

  return {
    detected: indicators.length > 0,
    indicators
  }
}

// Helper function to detect capitalization issues
function detectCapitalizationIssues(text: string): string[] {
  const issues: string[] = []

  // Check for inconsistent title case usage
  const sentences = text.split(/[.!?]+/)
  let allCaps = 0
  let allLower = 0
  let mixedCase = 0

  for (const sentence of sentences) {
    const trimmed = sentence.trim()
    if (trimmed.length < 5) continue

    if (trimmed === trimmed.toUpperCase()) allCaps++
    else if (trimmed === trimmed.toLowerCase()) allLower++
    else mixedCase++
  }

  const total = allCaps + allLower + mixedCase
  if (total > 5) {
    if (allCaps > 0 && allLower > 0 && mixedCase > 0) {
      issues.push('Inconsistent capitalization styles throughout document')
    }
  }

  return issues
}

// Helper function to check if document is financial
function isFinancialDocument(fileName: string, text: string): boolean {
  const financialKeywords = [
    'invoice', 'bill', 'receipt', 'payment', 'amount', 'total',
    'balance', 'statement', 'account', 'transaction', 'tax',
    'credit', 'debit', 'bank', 'transfer', 'wire', 'remittance'
  ]

  const lowerFileName = fileName.toLowerCase()
  const lowerText = text.toLowerCase()

  // Check filename
  for (const keyword of financialKeywords) {
    if (lowerFileName.includes(keyword)) return true
  }

  // Check content - need at least 3 keywords
  let keywordCount = 0
  for (const keyword of financialKeywords) {
    if (lowerText.includes(keyword)) keywordCount++
  }

  return keywordCount >= 3
}

// Helper function to detect financial document type
function detectFinancialDocumentType(fileName: string, text: string): 'invoice' | 'bank_statement' | 'receipt' | 'tax_document' | 'contract' | 'other' {
  const lowerFileName = fileName.toLowerCase()
  const lowerText = text.toLowerCase()

  if (lowerFileName.includes('invoice') || lowerText.includes('invoice number')) return 'invoice'
  if (lowerFileName.includes('statement') || lowerText.includes('account statement')) return 'bank_statement'
  if (lowerFileName.includes('receipt') || lowerText.includes('receipt')) return 'receipt'
  if (lowerFileName.includes('tax') || lowerText.includes('tax return')) return 'tax_document'
  if (lowerFileName.includes('contract') || lowerText.includes('agreement')) return 'contract'

  return 'other'
}

// Main authenticity analysis function
export function generateAuthenticityAnalysis(context: DetectionContext): AuthenticityAnalysis {
  const metadataAnalysis = analyzeMetadataAuthenticity(context)
  const contentAnalysis = analyzeContentAuthenticity(context)
  const financialChecks = analyzeFinancialDocument(context)

  // Compile red flags
  const redFlags: AuthenticityAnalysis['redFlags'] = []

  // Add metadata anomalies as red flags
  for (const anomaly of metadataAnalysis.anomalies) {
    redFlags.push({
      type: 'metadata_tampering',
      title: `Metadata Issue: ${anomaly.field}`,
      description: anomaly.issue,
      severity: anomaly.severity,
      confidence: 0.8,
      evidence: [`Field: ${anomaly.field}`],
      recommendation: 'Verify document source and request original document if possible'
    })
  }

  // Add content issues as red flags
  for (const issue of contentAnalysis.issues) {
    const typeMap: Record<string, AuthenticityAnalysis['redFlags'][0]['type']> = {
      'format_inconsistency': 'format_anomaly',
      'amount_anomaly': 'content_inconsistency',
      'currency_inconsistency': 'content_inconsistency',
      'copy_paste': 'copy_paste_detected',
      'suspicious_phrase': 'content_inconsistency',
      'capitalization': 'format_anomaly',
      'content': 'content_inconsistency'
    }

    redFlags.push({
      type: typeMap[issue.type] || 'other',
      title: issue.type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      description: issue.description,
      severity: issue.severity,
      confidence: 0.75,
      evidence: [`Location: ${issue.location}`],
      recommendation: 'Cross-reference with original source or request verification'
    })
  }

  // Calculate overall score (weighted average)
  const metadataWeight = 0.4
  const contentWeight = 0.6
  const overallScore = Math.round(
    (metadataAnalysis.score * metadataWeight) +
    (contentAnalysis.score * contentWeight)
  )

  // Determine fraud risk level
  let fraudRiskLevel: AuthenticityAnalysis['fraudRiskLevel'] = 'low'
  if (overallScore < 40) fraudRiskLevel = 'critical'
  else if (overallScore < 60) fraudRiskLevel = 'high'
  else if (overallScore < 80) fraudRiskLevel = 'medium'

  // Determine verdict
  let verdict: AuthenticityAnalysis['verdict'] = 'authentic'
  if (overallScore < 30) verdict = 'fraudulent'
  else if (overallScore < 50) verdict = 'likely_fraudulent'
  else if (overallScore < 70) verdict = 'suspicious'
  else if (overallScore < 85) verdict = 'likely_authentic'

  // Generate recommendations
  const recommendations: AuthenticityAnalysis['recommendations'] = []

  if (fraudRiskLevel === 'critical' || fraudRiskLevel === 'high') {
    recommendations.push({
      priority: 'critical',
      action: 'Do not accept this document without thorough verification',
      reason: 'Multiple indicators suggest this document may be fraudulent'
    })
  }

  if (!metadataAnalysis.timestampSequenceValid) {
    recommendations.push({
      priority: 'high',
      action: 'Request the original document from the issuing party',
      reason: 'Timestamp inconsistencies suggest document modification'
    })
  }

  if (!metadataAnalysis.softwareSignatureValid) {
    recommendations.push({
      priority: 'medium',
      action: 'Verify document authenticity with the original source',
      reason: 'Document appears to have been edited with PDF modification tools'
    })
  }

  if (financialChecks && !financialChecks.amountsValid) {
    recommendations.push({
      priority: 'high',
      action: 'Cross-verify all monetary amounts with source records',
      reason: 'Suspicious amount patterns detected'
    })
  }

  if (recommendations.length === 0) {
    recommendations.push({
      priority: 'low',
      action: 'Standard verification procedures are sufficient',
      reason: 'No significant authenticity concerns detected'
    })
  }

  // Generate summary
  let summary = ''
  if (verdict === 'authentic' || verdict === 'likely_authentic') {
    summary = `This document appears to be authentic with an authenticity score of ${overallScore}%. No significant red flags were detected during analysis.`
  } else if (verdict === 'suspicious') {
    summary = `This document shows some signs of potential modification with an authenticity score of ${overallScore}%. ${redFlags.length} concern(s) were identified that warrant further verification.`
  } else {
    summary = `WARNING: This document shows significant signs of potential fraud or manipulation with an authenticity score of only ${overallScore}%. ${redFlags.length} red flag(s) were identified. Exercise extreme caution and verify with original sources.`
  }

  return {
    overallScore,
    fraudRiskLevel,
    verdict,
    confidenceLevel: 0.85,

    originAnalysis: {
      likelySource: metadataAnalysis.softwareSignatureValid ? 'Legitimate document creation software' : 'Online PDF editor or modification tool',
      sourceConfidence: metadataAnalysis.softwareSignatureValid ? 0.8 : 0.6,
      isOriginalDocument: overallScore >= 85,
      possibleManipulation: overallScore < 70
    },

    redFlags,
    metadataAuthenticity: metadataAnalysis,
    contentAuthenticity: contentAnalysis,
    financialDocumentChecks: financialChecks,
    recommendations,
    summary
  }
}
