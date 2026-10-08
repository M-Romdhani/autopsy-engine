import type { AutopsyReport } from '../types.js'

export interface ComplianceScore {
  overall: number
  breakdown: {
    integrity: number
    metadata: number
    content: number
    regulations: number
    forensic: number
  }
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  summary: string
  details: string[]
}

export function calculateComplianceScore(report: AutopsyReport): ComplianceScore {
  const details: string[] = []

  // 1. Integrity Score (from integrity assessment)
  const integrityBase = (report.integrityAssessment.overallScore || 0.5) * 100
  const integrityPenalty = report.integrityAssessment.issues.reduce((p, i) => {
    const penalty = i.severity === 'high' ? 20 : i.severity === 'medium' ? 10 : 5
    details.push(`Integrity: -${penalty} for ${i.type} (${i.severity})`)
    return p + penalty
  }, 0)
  const integrityScore = Math.max(0, integrityBase - integrityPenalty)

  // 2. Metadata Score (from forensic insights)
  let metadataScore = 100
  for (const inconsistency of report.forensicInsights.metadataInconsistencies) {
    const penalty = inconsistency.severity === 'high' ? 25 : inconsistency.severity === 'medium' ? 15 : 8
    metadataScore -= penalty
    details.push(`Metadata: -${penalty} for ${inconsistency.field} issue`)
  }
  metadataScore = Math.max(0, metadataScore)

  // 3. Content Score (from suspicious patterns)
  let contentScore = 100
  for (const pattern of report.forensicInsights.suspiciousPatterns) {
    const penalty = pattern.severity === 'high' ? 25 : pattern.severity === 'medium' ? 15 : 8
    contentScore -= penalty
    details.push(`Content: -${penalty} for ${pattern.pattern}`)
  }
  contentScore = Math.max(0, contentScore)

  // 4. Regulations Score (from compliance analysis)
  const regulationsScore = report.complianceAnalysis.overallScore || 50
  if (report.complianceAnalysis.flags.length > 0) {
    details.push(`Regulations: ${report.complianceAnalysis.flags.length} compliance flag(s) found`)
  }

  // 5. Forensic Score (from authenticity analysis)
  let forensicScore = 100
  if (report.authenticityAnalysis) {
    forensicScore = report.authenticityAnalysis.overallScore
    if (report.authenticityAnalysis.redFlags.length > 0) {
      details.push(`Forensic: ${report.authenticityAnalysis.redFlags.length} red flag(s) detected`)
    }
  }

  // Calculate weighted overall score
  const weights = {
    integrity: 0.20,
    metadata: 0.15,
    content: 0.20,
    regulations: 0.20,
    forensic: 0.25
  }

  const overall = Math.round(
    integrityScore * weights.integrity +
    metadataScore * weights.metadata +
    contentScore * weights.content +
    regulationsScore * weights.regulations +
    forensicScore * weights.forensic
  )

  // Determine grade
  const grade = overall >= 90 ? 'A' : overall >= 80 ? 'B' : overall >= 70 ? 'C' : overall >= 60 ? 'D' : 'F'

  // Generate dynamic summary
  let summary: string
  if (overall >= 90) {
    summary = 'Document passes all compliance checks with excellent scores across all categories.'
  } else if (overall >= 80) {
    summary = 'Document is generally compliant with minor issues that should be reviewed.'
  } else if (overall >= 70) {
    summary = 'Document has some compliance concerns that require attention before acceptance.'
  } else if (overall >= 60) {
    summary = 'Document has notable compliance issues. Detailed review recommended.'
  } else if (overall >= 40) {
    summary = 'Document has significant compliance failures. Do not accept without verification.'
  } else {
    summary = 'CRITICAL: Document fails multiple compliance checks. High risk of fraud or manipulation.'
  }

  return {
    overall,
    breakdown: {
      integrity: Math.round(integrityScore),
      metadata: Math.round(metadataScore),
      content: Math.round(contentScore),
      regulations: Math.round(regulationsScore),
      forensic: Math.round(forensicScore)
    },
    grade,
    summary,
    details
  }
}

export function getComplianceRecommendations(report: AutopsyReport): string[] {
  const recommendations: string[] = []

  // From compliance flags
  for (const flag of report.complianceAnalysis.flags) {
    if (flag.recommendation && !recommendations.includes(flag.recommendation)) {
      recommendations.push(flag.recommendation)
    }
  }

  // From authenticity analysis
  if (report.authenticityAnalysis) {
    for (const rec of report.authenticityAnalysis.recommendations) {
      if (!recommendations.includes(rec.action)) {
        recommendations.push(rec.action)
      }
    }
  }

  // From integrity issues
  if (report.integrityAssessment.overallScore < 0.7) {
    recommendations.push('Verify document authenticity with the original issuing party')
  }

  // From forensic insights
  if (report.forensicInsights.metadataInconsistencies.some(i => i.severity === 'high')) {
    recommendations.push('Investigate metadata inconsistencies - possible document tampering')
  }

  if (report.forensicInsights.suspiciousPatterns.some(p => p.severity === 'high')) {
    recommendations.push('Review suspicious content patterns identified in the document')
  }

  // Default recommendation if none found
  if (recommendations.length === 0) {
    recommendations.push('Document appears compliant - standard verification procedures apply')
  }

  return [...new Set(recommendations)]
}
