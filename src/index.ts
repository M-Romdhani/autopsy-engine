export { analyzeDocument, comparePdfs, detectFileType, PDF_TYPE, DOCX_TYPE } from './analyze.js'
export type { AnalyzeOptions, DocumentAnalysis } from './analyze.js'
export { generateAutopsyReport, generateMetadataEvents } from './ai/inference.js'
export type { AiOptions, AnalysisInput } from './ai/inference.js'
export type { DetectionContext, MetadataAnalysisResult, ContentAnalysisResult } from './authenticity/detector.js'
export {
  analyzeMetadataAuthenticity,
  analyzeContentAuthenticity,
  analyzeFinancialDocument,
  generateAuthenticityAnalysis,
} from './authenticity/detector.js'
export { generateEnhancedAuthenticityAnalysis, quickForensicCheck } from './authenticity/enhancedDetector.js'
export type { EnhancedAuthenticityAnalysis, EnhancedDetectionContext } from './authenticity/enhancedDetector.js'
export { calculateComplianceScore, getComplianceRecommendations } from './compliance/score.js'
export type { ComplianceScore } from './compliance/score.js'
export { computeTextDiff, calculateSimilarity } from './diff/sectionDiff.js'
export { analyzePDFForensics, comparePDFsForensically } from './forensics/pdfForensics.js'
export type { PDFForensicResult, ComparisonResult, RedFlag, FontInfo } from './forensics/pdfForensics.js'
export { extractPdfMetadata } from './metadata/pdf.js'
export { extractDocxMetadata } from './metadata/docx.js'
export type * from './types.js'
