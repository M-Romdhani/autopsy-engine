import type { AutopsyReport, DocumentMetadata, EditEvent, AuthenticityAnalysis } from '../types.js'
import { generateId } from '../util.js'
import { generateAuthenticityAnalysis } from '../authenticity/detector.js'

export interface AnalysisInput {
  fileName: string
  fileType: string
  fileSize: number
  extractedText: string
  metadata: DocumentMetadata
  events: EditEvent[]
  buffer?: Buffer
  /** Gemini enhancement. `false` keeps the analysis fully local. */
  ai?: AiOptions | false
}

export interface AiOptions {
  /** Defaults to the GEMINI_API_KEY environment variable. */
  apiKey?: string
  /** Defaults to GEMINI_MODEL, then gemini-2.5-flash. */
  model?: string
}

// =============================================================================
// GEMINI API
// =============================================================================

async function analyzeWithGemini(prompt: string, options: AiOptions = {}): Promise<Record<string, unknown> | null> {
  const apiKey = options.apiKey ?? process.env.GEMINI_API_KEY
  if (!apiKey) return null
  const model = options.model ?? process.env.GEMINI_MODEL ?? 'gemini-2.5-flash'

  try {
    // The key travels in a header, never the URL, so it stays out of proxy and access logs.
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': apiKey },
        body: JSON.stringify({
          contents: [{
            parts: [{ text: prompt }]
          }],
          generationConfig: {
            temperature: 0.3,
            topK: 40,
            topP: 0.95,
            maxOutputTokens: 2048,
          }
        })
      }
    )

    if (!response.ok) {
      console.error('Gemini API error:', response.status, await response.text())
      return null
    }

    const data = (await response.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>
    }
    const text = data.candidates?.[0]?.content?.parts?.[0]?.text

    if (!text) return null

    // Parse JSON from response (handle markdown code blocks)
    const cleaned = text.replace(/```json\n?|\n?```/g, '').trim()
    return JSON.parse(cleaned)
  } catch (error) {
    console.error('Gemini error:', error)
    return null
  }
}

// =============================================================================
// DOCUMENT PATTERNS
// =============================================================================

const DOCUMENT_PATTERNS = {
  invoice: { keywords: ['invoice', 'bill to', 'amount due', 'payment', 'subtotal', 'total', 'qty', 'unit price'], weight: 2 },
  receipt: { keywords: ['receipt', 'transaction', 'paid', 'change', 'cashier'], weight: 2 },
  contract: { keywords: ['agreement', 'terms', 'conditions', 'party', 'whereas', 'hereby'], weight: 2 },
  report: { keywords: ['report', 'summary', 'analysis', 'findings', 'conclusion'], weight: 1.5 },
  letter: { keywords: ['dear', 'sincerely', 'regards', 'yours truly'], weight: 1.5 },
  financial: { keywords: ['balance', 'credit', 'debit', 'account', 'statement'], weight: 2 }
}

const SUSPICIOUS_PHRASES = [
  'wire transfer immediately', 'urgent payment required', 'account suspended',
  'verify your account', 'click here to confirm', 'act now', 'limited time'
]

// =============================================================================
// MAIN ANALYSIS FUNCTION
// =============================================================================

export async function generateAutopsyReport(input: AnalysisInput): Promise<Omit<AutopsyReport, 'id' | 'documentId'>> {
  const startTime = Date.now()

  // Always run local authenticity analysis (fast, no API needed)
  const authenticityAnalysis = generateAuthenticityAnalysis({
    metadata: input.metadata,
    text: input.extractedText,
    fileName: input.fileName,
    fileType: input.fileType,
    fileSize: input.fileSize,
    events: input.events
  })

  // Local analysis (always runs)
  const documentClassification = classifyDocument(input)
  let contentAnalysis = analyzeContentLocally(input)
  const integrityAssessment = assessIntegrity(input, authenticityAnalysis)
  let complianceAnalysis = analyzeComplianceLocally(input, authenticityAnalysis, documentClassification)
  const forensicInsights = generateForensicInsights(input, authenticityAnalysis)

  // Try Gemini enhancement
  let aiProvider = 'local'

  const geminiResult = input.ai === false
    ? null
    : await analyzeWithGemini(buildGeminiPrompt(input, authenticityAnalysis), input.ai)

  if (geminiResult) {
    aiProvider = 'gemini'

    // Merge Gemini insights
    const geminiContent = geminiResult.contentAnalysis as Record<string, unknown> | undefined
    if (geminiContent) {
      contentAnalysis = {
        ...contentAnalysis,
        summary: (geminiContent.summary as string) || contentAnalysis.summary,
        keyTopics: (geminiContent.keyTopics as string[]) || contentAnalysis.keyTopics,
        sentiment: geminiContent.sentiment ? {
          score: ((geminiContent.sentiment as Record<string, unknown>).score as number) || 0,
          label: ((geminiContent.sentiment as Record<string, unknown>).label as string) || 'neutral',
          confidence: 0.85
        } : contentAnalysis.sentiment
      }
    }

    const geminiCompliance = geminiResult.complianceAnalysis as Record<string, unknown> | undefined
    if (geminiCompliance) {
      complianceAnalysis = {
        overallScore: (geminiCompliance.overallScore as number) ?? complianceAnalysis.overallScore,
        flags: (geminiCompliance.flags as AutopsyReport['complianceAnalysis']['flags']) || complianceAnalysis.flags,
        regulations: (geminiCompliance.regulations as AutopsyReport['complianceAnalysis']['regulations']) || complianceAnalysis.regulations
      }
    }

    const geminiForensics = geminiResult.forensicInsights as Record<string, unknown> | undefined
    if (geminiForensics?.suspiciousPatterns) {
      const patterns = geminiForensics.suspiciousPatterns as Array<Record<string, unknown>>
      forensicInsights.suspiciousPatterns = [
        ...forensicInsights.suspiciousPatterns,
        ...patterns.map((p) => ({
          pattern: (p.pattern as string) || 'ai_detected',
          description: (p.description as string) || String(p),
          confidence: 0.8,
          severity: (p.severity as 'low' | 'medium' | 'high') || 'medium',
          relatedEvents: [] as string[]
        }))
      ]
    }
  }

  return {
    reportVersion: 1,
    generatedAt: Date.now(),
    processingTimeMs: Date.now() - startTime,
    analysisVersion: `2.2.0-${aiProvider}`,
    eventCount: input.events.length,
    authenticityAnalysis,
    documentClassification,
    contentAnalysis,
    editingTimeline: generateEditingTimeline(input.events),
    integrityAssessment,
    complianceAnalysis,
    forensicInsights
  }
}

// =============================================================================
// GEMINI PROMPT BUILDER
// =============================================================================

function buildGeminiPrompt(input: AnalysisInput, auth: AuthenticityAnalysis): string {
  return `You are a document forensics expert. Analyze this document and return ONLY valid JSON.

DOCUMENT INFO:
- Filename: ${input.fileName}
- Type: ${input.fileType}
- Size: ${input.fileSize} bytes

METADATA:
- Author: ${input.metadata.author || 'Unknown'}
- Created: ${input.metadata.creationDate || 'Unknown'}
- Modified: ${input.metadata.modificationDate || 'Unknown'}
- Creator Tool: ${input.metadata.creator || 'Unknown'}
- Producer: ${input.metadata.producer || 'Unknown'}

PRELIMINARY ANALYSIS:
- Authenticity Score: ${auth.overallScore}%
- Verdict: ${auth.verdict}
- Risk Level: ${auth.fraudRiskLevel}
- Red Flags: ${auth.redFlags.length}

DOCUMENT CONTENT (first 2000 chars):
${input.extractedText.substring(0, 2000)}

Return this exact JSON structure:
{
  "contentAnalysis": {
    "summary": "2-3 sentence summary of the document",
    "keyTopics": ["topic1", "topic2", "topic3", "topic4", "topic5"],
    "sentiment": {
      "label": "positive|negative|neutral",
      "score": -1.0 to 1.0
    },
    "language": "detected language",
    "documentPurpose": "what this document is for"
  },
  "complianceAnalysis": {
    "overallScore": 0-100,
    "flags": [
      {
        "type": "flag_type",
        "description": "what the issue is",
        "severity": "low|medium|high",
        "confidence": 0.0-1.0,
        "recommendation": "what to do about it"
      }
    ],
    "regulations": [
      {
        "regulation": "regulation name",
        "compliance": "compliant|non_compliant|unclear",
        "confidence": 0.0-1.0,
        "details": "explanation"
      }
    ]
  },
  "forensicInsights": {
    "suspiciousPatterns": [
      {
        "pattern": "pattern_type",
        "description": "what was found",
        "severity": "low|medium|high"
      }
    ],
    "manipulationIndicators": ["indicator1", "indicator2"],
    "recommendations": ["recommendation1", "recommendation2"]
  },
  "fraudAssessment": {
    "isSuspicious": true|false,
    "confidence": 0.0-1.0,
    "reasons": ["reason1", "reason2"]
  }
}`
}

// =============================================================================
// LOCAL ANALYSIS FUNCTIONS
// =============================================================================

function classifyDocument(input: AnalysisInput): AutopsyReport['documentClassification'] {
  const text = input.extractedText.toLowerCase()
  const fileName = input.fileName.toLowerCase()

  let bestMatch = { type: 'General Document', confidence: 0.5, score: 0 }

  for (const [docType, pattern] of Object.entries(DOCUMENT_PATTERNS)) {
    let matchCount = 0
    for (const keyword of pattern.keywords) {
      if (text.includes(keyword) || fileName.includes(keyword)) matchCount++
    }

    const score = matchCount * pattern.weight
    if (score > bestMatch.score) {
      bestMatch = {
        type: docType.charAt(0).toUpperCase() + docType.slice(1),
        confidence: Math.min(0.95, 0.5 + (matchCount / pattern.keywords.length) * 0.45),
        score
      }
    }
  }

  return {
    type: bestMatch.type,
    confidence: bestMatch.confidence,
    reasoning: `Document classified as ${bestMatch.type} based on content keyword analysis.`
  }
}

function analyzeContentLocally(input: AnalysisInput): AutopsyReport['contentAnalysis'] {
  const text = input.extractedText
  const words = text.split(/\s+/).filter(Boolean)

  // Key topics extraction
  const wordFreq = new Map<string, number>()
  const stopWords = new Set(['the', 'a', 'an', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'to', 'of', 'in', 'for', 'on', 'with', 'at', 'by', 'from', 'as', 'and', 'but', 'or', 'this', 'that', 'it', 'its'])

  words.forEach(word => {
    const clean = word.toLowerCase().replace(/[^a-z]/g, '')
    if (clean.length > 3 && !stopWords.has(clean)) {
      wordFreq.set(clean, (wordFreq.get(clean) || 0) + 1)
    }
  })

  const keyTopics = [...wordFreq.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([word]) => word.charAt(0).toUpperCase() + word.slice(1))

  // Simple sentiment
  const positiveWords = ['good', 'great', 'excellent', 'thank', 'appreciate', 'success']
  const negativeWords = ['bad', 'poor', 'fail', 'problem', 'issue', 'urgent']

  let sentimentScore = 0
  const lowerText = text.toLowerCase()
  positiveWords.forEach(w => { if (lowerText.includes(w)) sentimentScore++ })
  negativeWords.forEach(w => { if (lowerText.includes(w)) sentimentScore-- })

  const normalizedSentiment = Math.max(-1, Math.min(1, sentimentScore / 5))

  return {
    summary: `Document "${input.fileName}" contains ${words.length} words.${keyTopics.length > 0 ? ` Key topics: ${keyTopics.slice(0, 3).join(', ')}.` : ''}`,
    keyTopics,
    sentiment: {
      score: normalizedSentiment,
      label: normalizedSentiment > 0.2 ? 'positive' : normalizedSentiment < -0.2 ? 'negative' : 'neutral',
      confidence: 0.7
    },
    language: 'English',
    readabilityScore: 70
  }
}

function assessIntegrity(input: AnalysisInput, auth: AuthenticityAnalysis): AutopsyReport['integrityAssessment'] {
  const issues: AutopsyReport['integrityAssessment']['issues'] = []
  const indicators: AutopsyReport['integrityAssessment']['authenticityIndicators'] = []

  for (const flag of auth.redFlags) {
    issues.push({
      type: flag.type,
      description: flag.description,
      severity: flag.severity === 'critical' ? 'high' : flag.severity,
      confidence: flag.confidence
    })
  }

  indicators.push({ indicator: 'Creation date present', present: !!input.metadata.creationDate, confidence: 0.9 })
  indicators.push({ indicator: 'Author information', present: !!input.metadata.author, confidence: 0.85 })
  indicators.push({ indicator: 'Software signature', present: !!(input.metadata.creator || input.metadata.producer), confidence: 0.8 })

  // Timestamp consistency
  if (input.metadata.creationDate && input.metadata.modificationDate) {
    const creation = new Date(input.metadata.creationDate).getTime()
    const modification = new Date(input.metadata.modificationDate).getTime()
    const match = Math.abs(creation - modification) < 60000
    indicators.push({ indicator: 'Timestamp consistency', present: match, confidence: 0.95 })
  }

  const overallScore = Math.max(0, 1 - (issues.length * 0.15))

  return { overallScore, issues, authenticityIndicators: indicators }
}

function analyzeComplianceLocally(
  input: AnalysisInput,
  auth: AuthenticityAnalysis,
  classification: AutopsyReport['documentClassification']
): AutopsyReport['complianceAnalysis'] {
  const flags: AutopsyReport['complianceAnalysis']['flags'] = []
  const regulations: AutopsyReport['complianceAnalysis']['regulations'] = []
  const text = input.extractedText.toLowerCase()

  // Check suspicious phrases
  for (const phrase of SUSPICIOUS_PHRASES) {
    if (text.includes(phrase)) {
      flags.push({
        type: 'suspicious_content',
        description: `Contains suspicious phrase: "${phrase}"`,
        severity: 'high',
        confidence: 0.9,
        recommendation: 'Verify document authenticity before taking action'
      })
    }
  }

  // Financial document checks
  if (['Invoice', 'Financial', 'Receipt'].includes(classification.type)) {
    const hasDate = /\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/.test(text)
    const hasAmount = /\$[\d,]+\.?\d*/.test(text)
    const hasReference = /(?:invoice|order|ref|account)\s*(?:#|no|number)?\s*:?\s*[\w-]+/i.test(text)

    if (!hasDate) {
      flags.push({
        type: 'missing_date',
        description: 'Financial document missing clear date',
        severity: 'medium',
        confidence: 0.8,
        recommendation: 'Verify document date with issuer'
      })
    }

    if (!hasReference) {
      flags.push({
        type: 'missing_reference',
        description: 'No invoice/reference number found',
        severity: 'medium',
        confidence: 0.75,
        recommendation: 'Verify document has proper reference number'
      })
    }

    regulations.push({
      regulation: 'Financial Record Requirements',
      compliance: hasDate && hasAmount && hasReference ? 'compliant' : 'non_compliant',
      confidence: 0.75,
      details: hasDate && hasAmount && hasReference ? 'Document meets basic requirements' : 'Missing required elements'
    })
  }

  // Authenticity-based compliance
  if (auth.fraudRiskLevel === 'high' || auth.fraudRiskLevel === 'critical') {
    flags.push({
      type: 'authenticity_concern',
      description: `Document authenticity score: ${auth.overallScore}%`,
      severity: 'high',
      confidence: auth.confidenceLevel,
      recommendation: 'Verify document with original source'
    })
  }

  const highFlags = flags.filter(f => f.severity === 'high').length
  const mediumFlags = flags.filter(f => f.severity === 'medium').length
  const overallScore = Math.max(0, 100 - (highFlags * 20) - (mediumFlags * 10))

  return { overallScore, flags, regulations }
}

function generateForensicInsights(
  input: AnalysisInput,
  auth: AuthenticityAnalysis
): AutopsyReport['forensicInsights'] {
  const suspiciousPatterns: AutopsyReport['forensicInsights']['suspiciousPatterns'] = []
  const metadataInconsistencies: AutopsyReport['forensicInsights']['metadataInconsistencies'] = []

  // From authenticity analysis
  for (const anomaly of auth.metadataAuthenticity.anomalies) {
    metadataInconsistencies.push({
      field: anomaly.field,
      issue: anomaly.issue,
      severity: anomaly.severity,
      confidence: 0.85
    })
  }

  // Check content for suspicious patterns
  const text = input.extractedText.toLowerCase()
  for (const phrase of SUSPICIOUS_PHRASES) {
    if (text.includes(phrase)) {
      suspiciousPatterns.push({
        pattern: 'suspicious_phrase',
        description: `Contains: "${phrase}"`,
        confidence: 0.85,
        severity: 'high',
        relatedEvents: []
      })
    }
  }

  // Check for editing tool signatures
  const producer = (input.metadata.producer || '').toLowerCase()
  const creator = (input.metadata.creator || '').toLowerCase()
  const suspiciousTools = ['smallpdf', 'ilovepdf', 'sejda', 'pdfescape', 'pdf2go', 'online']

  for (const tool of suspiciousTools) {
    if (producer.includes(tool) || creator.includes(tool)) {
      suspiciousPatterns.push({
        pattern: 'editing_tool',
        description: `Document processed with online editor: ${tool}`,
        confidence: 0.9,
        severity: 'high',
        relatedEvents: []
      })
      break
    }
  }

  return {
    suspiciousPatterns,
    toolAnalysis: {
      primaryTool: input.metadata.creator || input.metadata.producer || 'Unknown',
      toolConfidence: input.metadata.creator ? 0.8 : 0.4,
      toolSwitches: []
    },
    metadataInconsistencies
  }
}

function generateEditingTimeline(events: EditEvent[]): AutopsyReport['editingTimeline'] {
  return events
    .sort((a, b) => a.timestamp.value - b.timestamp.value)
    .map((event, index) => ({
      eventId: event.id,
      sequenceNumber: index + 1,
      estimatedTime: new Date(event.timestamp.value).toISOString(),
      description: event.description,
      confidence: event.confidence,
      evidence: event.evidence.map(e => e.description)
    }))
}

// =============================================================================
// METADATA EVENTS GENERATOR
// =============================================================================

export function generateMetadataEvents(
  documentId: string,
  metadata: DocumentMetadata,
  extractedText: string
): EditEvent[] {
  const events: EditEvent[] = []
  const now = Date.now()

  // Creation event
  if (metadata.creationDate) {
    const creationTime = new Date(metadata.creationDate).getTime()
    const suspiciousFlags: EditEvent['suspiciousFlags'] = []

    if (creationTime > now) {
      suspiciousFlags.push({
        flag: 'future_date',
        severity: 'high',
        description: 'Creation date is in the future'
      })
    }

    events.push({
      id: generateId(),
      documentId,
      source: 'metadata',
      confidence: 0.95,
      eventType: 'document_creation',
      description: 'Document created',
      timestamp: { value: creationTime, type: 'exact', confidence: 0.95 },
      inferredTool: metadata.creator || 'Unknown',
      toolConfidence: metadata.creator ? 0.8 : 0.3,
      evidence: [{ type: 'metadata', description: 'Creation date from metadata', confidence: 0.95 }],
      suspiciousFlags,
      createdAt: now
    })
  }

  // Modification event (if different from creation)
  if (metadata.modificationDate && metadata.creationDate) {
    const modTime = new Date(metadata.modificationDate).getTime()
    const createTime = new Date(metadata.creationDate).getTime()

    if (Math.abs(modTime - createTime) > 60000) {
      const timeDiff = Math.round((modTime - createTime) / 60000)

      events.push({
        id: generateId(),
        documentId,
        source: 'metadata',
        confidence: 0.9,
        eventType: 'document_modification',
        description: `Document modified ${timeDiff} minutes after creation`,
        timestamp: { value: modTime, type: 'exact', confidence: 0.9 },
        inferredTool: metadata.producer || 'Unknown',
        toolConfidence: 0.7,
        evidence: [{ type: 'metadata', description: 'Modification timestamp differs from creation', confidence: 0.9 }],
        suspiciousFlags: timeDiff > 60 ? [{
          flag: 'late_modification',
          severity: 'medium',
          description: `Modified ${timeDiff} minutes after creation`
        }] : [],
        createdAt: now
      })
    }
  }

  // Content event
  const wordCount = extractedText.split(/\s+/).filter(Boolean).length
  events.push({
    id: generateId(),
    documentId,
    source: 'ai_inference',
    confidence: 0.85,
    eventType: 'content_analysis',
    section: 'document_body',
    description: `Document contains ${wordCount} words`,
    timestamp: { value: now, type: 'exact', confidence: 1 },
    changeDetails: { changeType: 'addition', characterCount: extractedText.length, wordCount },
    evidence: [{ type: 'extraction', description: 'Text content extracted', confidence: 0.9 }],
    suspiciousFlags: [],
    createdAt: now
  })

  // Financial content event
  const amounts = extractedText.match(/\$[\d,]+\.?\d*/g) || []
  if (amounts.length > 0) {
    events.push({
      id: generateId(),
      documentId,
      source: 'ai_inference',
      confidence: 0.8,
      eventType: 'financial_content',
      section: 'amounts',
      description: `Found ${amounts.length} monetary amount(s): ${amounts.slice(0, 3).join(', ')}${amounts.length > 3 ? '...' : ''}`,
      timestamp: { value: now, type: 'inferred', confidence: 0.8 },
      evidence: [{ type: 'pattern', description: 'Currency amounts detected', confidence: 0.85 }],
      suspiciousFlags: [],
      createdAt: now
    })
  }

  return events
}
