export interface Document {
  id: string
  fileName: string
  fileSize: number
  fileType: string
  uploadedAt: number
  consentGiven: boolean
  status: 'uploaded' | 'processing' | 'analyzed' | 'error'
  errorMessage?: string
  metadata?: DocumentMetadata
}

export interface DocumentMetadata {
  creationDate?: string
  modificationDate?: string
  author?: string
  creator?: string
  producer?: string
  title?: string
  subject?: string
  keywords?: string
  pageCount?: number
  wordCount?: number
  revisionCount?: number
  totalEditTime?: number
}

export interface EditEvent {
  id: string
  documentId: string
  versionId?: string
  source: 'metadata' | 'diff' | 'ai_inference'
  confidence: number
  eventType: string
  section?: string
  description: string
  timestamp: {
    value: number
    type: 'exact' | 'inferred'
    confidence: number
  }
  inferredTool?: string
  toolConfidence?: number
  changeDetails?: {
    changeType: 'addition' | 'deletion' | 'modification'
    beforeText?: string
    afterText?: string
    characterCount?: number
    wordCount?: number
  }
  evidence: Array<{
    type: string
    description: string
    confidence: number
  }>
  suspiciousFlags: Array<{
    flag: string
    severity: 'low' | 'medium' | 'high'
    description: string
  }>
  createdAt: number
}

export interface AuthenticityAnalysis {
  overallScore: number // 0-100, where 100 = definitely authentic
  fraudRiskLevel: 'low' | 'medium' | 'high' | 'critical'
  verdict: 'authentic' | 'likely_authentic' | 'suspicious' | 'likely_fraudulent' | 'fraudulent'
  confidenceLevel: number

  // Document origin analysis
  originAnalysis: {
    likelySource: string
    sourceConfidence: number
    isOriginalDocument: boolean
    possibleManipulation: boolean
  }

  // Red flags for fraud detection
  redFlags: Array<{
    type: 'metadata_tampering' | 'content_inconsistency' | 'format_anomaly' |
          'timestamp_mismatch' | 'copy_paste_detected' | 'font_inconsistency' |
          'image_manipulation' | 'signature_issue' | 'template_mismatch' | 'other'
    title: string
    description: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    confidence: number
    evidence: string[]
    recommendation: string
  }>

  // Metadata authenticity checks
  metadataAuthenticity: {
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

  // Content authenticity checks
  contentAuthenticity: {
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

  // For financial documents (bills, invoices, bank statements)
  financialDocumentChecks?: {
    isFinancialDocument: boolean
    documentType?: 'invoice' | 'bank_statement' | 'receipt' | 'tax_document' | 'contract' | 'other'
    currencyConsistent: boolean
    amountsValid: boolean
    dateFormatsConsistent: boolean
    logoPresent: boolean
    referenceNumbersValid: boolean
    suspiciousAmounts: Array<{
      amount: string
      reason: string
    }>
  }

  // Recommendations for the user
  recommendations: Array<{
    priority: 'low' | 'medium' | 'high' | 'critical'
    action: string
    reason: string
  }>

  // Summary for easy understanding
  summary: string
}

// PDF Forensic Analysis Types
export interface PDFForensicAnalysis {
  sizeAnalysis: {
    fileSize: number
    expectedSizeRange: { min: number; max: number }
    sizeAnomaly: boolean
    sizeAnomalyReason?: string
    sizeRatio?: number
    sizeScore: number
  }

  fontAnalysis: {
    fonts: Array<{
      name: string
      isSubset: boolean
      subsetPrefix?: string
      isEmbedded: boolean
      type: 'original' | 'added' | 'unknown'
      suspicionLevel: 'none' | 'low' | 'medium' | 'high'
      reason?: string
    }>
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

  redFlags: Array<{
    type: string
    title: string
    description: string
    severity: 'low' | 'medium' | 'high' | 'critical'
    confidence: number
    technicalDetails: string
    recommendation: string
  }>

  overallScore: number
  riskLevel: 'low' | 'medium' | 'high' | 'critical'
  verdict: 'authentic' | 'likely_authentic' | 'suspicious' | 'likely_modified' | 'modified'
  summary: string
}

export interface PDFComparisonResult {
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

export interface AutopsyReport {
  id: string
  documentId: string
  reportVersion: number
  generatedAt: number
  processingTimeMs: number
  analysisVersion: string
  eventCount: number

  // NEW: Authenticity and fraud detection analysis
  authenticityAnalysis?: AuthenticityAnalysis

  // NEW: Advanced PDF forensic analysis
  pdfForensicAnalysis?: PDFForensicAnalysis

  // NEW: Comparison with reference document
  comparisonAnalysis?: PDFComparisonResult

  documentClassification: {
    type: string
    confidence: number
    reasoning: string
  }
  
  contentAnalysis: {
    summary: string
    keyTopics: string[]
    sentiment: {
      score: number
      label: string
      confidence: number
    }
    language?: string
    readabilityScore?: number
  }
  
  editingTimeline: Array<{
    eventId: string
    sequenceNumber: number
    estimatedTime: string
    description: string
    confidence: number
    evidence: string[]
  }>
  
  integrityAssessment: {
    overallScore: number
    issues: Array<{
      type: string
      description: string
      severity: 'low' | 'medium' | 'high'
      confidence: number
    }>
    authenticityIndicators: Array<{
      indicator: string
      present: boolean
      confidence: number
    }>
  }
  
  complianceAnalysis: {
    overallScore: number
    flags: Array<{
      type: string
      description: string
      severity: 'low' | 'medium' | 'high'
      confidence: number
      recommendation: string
    }>
    regulations: Array<{
      regulation: string
      compliance: 'compliant' | 'non_compliant' | 'unclear'
      confidence: number
      details: string
    }>
  }
  
  forensicInsights: {
    suspiciousPatterns: Array<{
      pattern: string
      description: string
      confidence: number
      severity: 'low' | 'medium' | 'high'
      relatedEvents: string[]
    }>
    toolAnalysis: {
      primaryTool?: string
      toolConfidence?: number
      toolSwitches: Array<{
        fromTool: string
        toTool: string
        timestamp: number
        confidence: number
      }>
    }
    metadataInconsistencies: Array<{
      field: string
      issue: string
      severity: 'low' | 'medium' | 'high'
      confidence: number
    }>
  }
}
