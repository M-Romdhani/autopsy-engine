import type { DocumentMetadata } from '../types.js'

export async function extractDocxMetadata(buffer: Buffer): Promise<{
  metadata: DocumentMetadata
  text: string
}> {
  try {
    const mammoth = (await import('mammoth')).default
    const result = await mammoth.extractRawText({ buffer })
    const text = result.value || ''
    const wordCount = text.split(/\s+/).filter(Boolean).length
    const metadata = await parseDocxCoreXml(buffer)
    
    return {
      metadata: { ...metadata, wordCount },
      text
    }
  } catch (error) {
    console.error('DOCX parsing error:', error)
    return { metadata: {}, text: '' }
  }
}

async function parseDocxCoreXml(buffer: Buffer): Promise<DocumentMetadata> {
  try {
    const JSZip = (await import('jszip')).default
    const zip = await JSZip.loadAsync(buffer)
    const coreXml = await zip.file('docProps/core.xml')?.async('text')
    
    if (!coreXml) return {}
    
    const metadata: DocumentMetadata = {}
    
    const titleMatch = coreXml.match(/<dc:title>([^<]*)<\/dc:title>/i)
    if (titleMatch) metadata.title = titleMatch[1]
    
    const authorMatch = coreXml.match(/<dc:creator>([^<]*)<\/dc:creator>/i)
    if (authorMatch) metadata.author = authorMatch[1]
    
    const createdMatch = coreXml.match(/<dcterms:created[^>]*>([^<]*)<\/dcterms:created>/i)
    if (createdMatch) metadata.creationDate = createdMatch[1]
    
    const modifiedMatch = coreXml.match(/<dcterms:modified[^>]*>([^<]*)<\/dcterms:modified>/i)
    if (modifiedMatch) metadata.modificationDate = modifiedMatch[1]
    
    const revisionMatch = coreXml.match(/<cp:revision>([^<]*)<\/cp:revision>/i)
    if (revisionMatch) metadata.revisionCount = parseInt(revisionMatch[1], 10)
    
    const appXml = await zip.file('docProps/app.xml')?.async('text')
    if (appXml) {
      const pagesMatch = appXml.match(/<Pages>(\d+)<\/Pages>/i)
      if (pagesMatch) metadata.pageCount = parseInt(pagesMatch[1], 10)
      
      const appNameMatch = appXml.match(/<Application>([^<]*)<\/Application>/i)
      if (appNameMatch) metadata.creator = appNameMatch[1]
      
      const totalTimeMatch = appXml.match(/<TotalTime>(\d+)<\/TotalTime>/i)
      if (totalTimeMatch) metadata.totalEditTime = parseInt(totalTimeMatch[1], 10) * 60
    }
    
    return metadata
  } catch (error) {
    console.error('Error parsing DOCX XML:', error)
    return {}
  }
}
