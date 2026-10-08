/**
 * Enhanced Authenticity Detector with PDF Forensic Integration
 *
 * Combines content-based analysis with low-level PDF forensics
 * for comprehensive fraud detection.
 */

import { DocumentMetadata, EditEvent, AuthenticityAnalysis } from '../types.js'
import { generateAuthenticityAnalysis } from './detector.js'
import { analyzePDFForensics, comparePDFsForensically, PDFForensicResult, ComparisonResult } from '../forensics/pdfForensics.js'

export interface EnhancedDetectionContext {
  metadata?: DocumentMetadata
  text: string
  fileName: string
  fileType: string
  fileSize: number
  events?: EditEvent[]
  // NEW: For PDF forensic analysis
  buffer?: Buffer
  // NEW: For comparison with reference document
  referenceBuffer?: Buffer
  referenceFileName?: string
}

export interface EnhancedAuthenticityAnalysis extends AuthenticityAnalysis {
  // NEW: Detailed PDF forensic analysis
  forensicAnalysis?: PDFForensicResult
  // NEW: Comparison with reference document
  comparisonAnalysis?: ComparisonResult
}

/**
 * Generate enhanced authenticity analysis with PDF forensics
 */
export function generateEnhancedAuthenticityAnalysis(
  context: EnhancedDetectionContext
): EnhancedAuthenticityAnalysis {
  // Start with base authenticity analysis
  const baseAnalysis = generateAuthenticityAnalysis({
    metadata: context.metadata,
    text: context.text,
    fileName: context.fileName,
    fileType: context.fileType,
    fileSize: context.fileSize,
    events: context.events
  })

  // If we have a PDF buffer, perform forensic analysis
  let forensicAnalysis: PDFForensicResult | undefined
  let comparisonAnalysis: ComparisonResult | undefined

  const isPDF = context.fileType.toLowerCase().includes('pdf')

  if (isPDF && context.buffer) {
    // Perform PDF forensic analysis
    forensicAnalysis = analyzePDFForensics({
      buffer: context.buffer,
      fileName: context.fileName,
      referenceSize: context.referenceBuffer?.length
    })

    // If we have a reference document, perform comparison
    if (context.referenceBuffer && context.referenceFileName) {
      comparisonAnalysis = comparePDFsForensically(
        context.referenceBuffer,
        context.buffer,
        context.referenceFileName,
        context.fileName
      )
    }

    // Integrate forensic findings into the analysis
    return integrateForensicFindings(baseAnalysis, forensicAnalysis, comparisonAnalysis)
  }

  // For non-PDF documents, return base analysis with optional fields
  return {
    ...baseAnalysis,
    forensicAnalysis: undefined,
    comparisonAnalysis: undefined
  }
}

/**
 * Integrate forensic findings into the overall authenticity analysis
 */
function integrateForensicFindings(
  baseAnalysis: AuthenticityAnalysis,
  forensicAnalysis: PDFForensicResult,
  comparisonAnalysis?: ComparisonResult
): EnhancedAuthenticityAnalysis {
  // Weight: 60% forensic, 40% content analysis
  const forensicWeight = 0.6
  const contentWeight = 0.4

  const combinedScore = Math.round(
    forensicAnalysis.overallScore * forensicWeight +
    baseAnalysis.overallScore * contentWeight
  )

  // Merge red flags from forensic analysis
  const forensicRedFlags = forensicAnalysis.redFlags.map(flag => ({
    type: mapForensicFlagType(flag.type),
    title: flag.title,
    description: flag.description,
    severity: flag.severity as 'low' | 'medium' | 'high' | 'critical',
    confidence: flag.confidence,
    evidence: [flag.technicalDetails],
    recommendation: flag.recommendation
  }))

  const allRedFlags = [...baseAnalysis.redFlags, ...forensicRedFlags]

  // Determine combined verdict
  let combinedVerdict: AuthenticityAnalysis['verdict']
  if (combinedScore >= 85) {
    combinedVerdict = 'authentic'
  } else if (combinedScore >= 70) {
    combinedVerdict = 'likely_authentic'
  } else if (combinedScore >= 50) {
    combinedVerdict = 'suspicious'
  } else if (combinedScore >= 30) {
    combinedVerdict = 'likely_fraudulent'
  } else {
    combinedVerdict = 'fraudulent'
  }

  // Determine combined risk level
  let combinedRiskLevel: AuthenticityAnalysis['fraudRiskLevel']
  if (combinedScore >= 80) {
    combinedRiskLevel = 'low'
  } else if (combinedScore >= 60) {
    combinedRiskLevel = 'medium'
  } else if (combinedScore >= 40) {
    combinedRiskLevel = 'high'
  } else {
    combinedRiskLevel = 'critical'
  }

  // Enhanced recommendations based on forensic findings
  const enhancedRecommendations = [...baseAnalysis.recommendations]

  if (forensicAnalysis.fontAnalysis.hasFontMismatch) {
    enhancedRecommendations.unshift({
      priority: 'high',
      action: 'Compare font sets with known authentic documents',
      reason: 'New fonts detected that were not in the original document'
    })
  }

  if (forensicAnalysis.structureAnalysis.hasEditingMarkers) {
    enhancedRecommendations.unshift({
      priority: 'critical',
      action: 'Request original document directly from the source',
      reason: `PDF editing tool signatures detected: ${forensicAnalysis.structureAnalysis.editingMarkers.join(', ')}`
    })
  }

  if (forensicAnalysis.timestampAnalysis.hasModificationAfterCreation) {
    enhancedRecommendations.unshift({
      priority: 'high',
      action: 'Verify document timeline with issuing party',
      reason: `Document was modified ${forensicAnalysis.timestampAnalysis.timeDifferenceMinutes} minutes after creation`
    })
  }

  if (comparisonAnalysis && comparisonAnalysis.overallRisk !== 'low') {
    enhancedRecommendations.unshift({
      priority: comparisonAnalysis.overallRisk === 'critical' ? 'critical' : 'high',
      action: 'Document differs significantly from reference',
      reason: comparisonAnalysis.verdict
    })
  }

  // Generate enhanced summary
  let summary = forensicAnalysis.summary
  if (comparisonAnalysis) {
    summary += ` Comparison analysis: ${comparisonAnalysis.verdict}`
  }

  // Enhanced metadata authenticity
  const enhancedMetadataAuthenticity = {
    ...baseAnalysis.metadataAuthenticity,
    score: Math.round(
      (baseAnalysis.metadataAuthenticity.score + forensicAnalysis.timestampAnalysis.timestampScore) / 2
    )
  }

  // Add forensic anomalies to metadata anomalies
  if (forensicAnalysis.timestampAnalysis.timestampAnomaly) {
    enhancedMetadataAuthenticity.anomalies.push({
      field: 'timestamps',
      issue: forensicAnalysis.timestampAnalysis.timestampAnomalyReason || 'Timestamp anomaly detected',
      severity: forensicAnalysis.timestampAnalysis.hasModificationAfterCreation ? 'high' : 'medium'
    })
  }

  // Enhanced content authenticity
  const enhancedContentAuthenticity = {
    ...baseAnalysis.contentAuthenticity,
    score: Math.round(
      (baseAnalysis.contentAuthenticity.score + forensicAnalysis.fontAnalysis.fontScore) / 2
    )
  }

  // Add font issues to content issues
  if (forensicAnalysis.fontAnalysis.suspiciousFonts.length > 0) {
    enhancedContentAuthenticity.issues.push({
      type: 'font_forensics',
      location: 'document',
      description: `Suspicious fonts detected: ${forensicAnalysis.fontAnalysis.suspiciousFonts.join(', ')}`,
      severity: 'high'
    })
  }

  return {
    overallScore: combinedScore,
    fraudRiskLevel: combinedRiskLevel,
    verdict: combinedVerdict,
    confidenceLevel: Math.max(baseAnalysis.confidenceLevel, 0.9), // Forensics increases confidence

    originAnalysis: {
      likelySource: forensicAnalysis.structureAnalysis.hasEditingMarkers
        ? `PDF editing tool (${forensicAnalysis.structureAnalysis.editingMarkers.join(', ')})`
        : forensicAnalysis.structureAnalysis.producer || baseAnalysis.originAnalysis.likelySource,
      sourceConfidence: forensicAnalysis.structureAnalysis.hasEditingMarkers ? 0.95 : 0.8,
      isOriginalDocument: combinedScore >= 80,
      possibleManipulation: combinedScore < 70
    },

    redFlags: allRedFlags,
    metadataAuthenticity: enhancedMetadataAuthenticity,
    contentAuthenticity: enhancedContentAuthenticity,
    financialDocumentChecks: baseAnalysis.financialDocumentChecks,
    recommendations: enhancedRecommendations,
    summary,

    // NEW: Forensic analysis details
    forensicAnalysis,
    comparisonAnalysis
  }
}

/**
 * Map forensic flag types to authenticity flag types
 */
function mapForensicFlagType(
  forensicType: string
): AuthenticityAnalysis['redFlags'][0]['type'] {
  const mapping: Record<string, AuthenticityAnalysis['redFlags'][0]['type']> = {
    'size_anomaly': 'format_anomaly',
    'font_manipulation': 'font_inconsistency',
    'timestamp_mismatch': 'timestamp_mismatch',
    'link_anomaly': 'format_anomaly',
    'structure_anomaly': 'metadata_tampering',
    'editing_markers': 'metadata_tampering'
  }

  return mapping[forensicType] || 'other'
}

/**
 * Quick forensic check for a PDF document
 * Returns a simplified risk assessment
 */
export function quickForensicCheck(buffer: Buffer, fileName: string): {
  score: number
  risk: 'low' | 'medium' | 'high' | 'critical'
  issues: string[]
} {
  const result = analyzePDFForensics({ buffer, fileName })

  return {
    score: result.overallScore,
    risk: result.riskLevel,
    issues: result.redFlags.map(f => f.title)
  }
}
