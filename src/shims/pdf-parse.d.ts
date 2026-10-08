// pdf-parse's package entry runs a debug self-test when loaded outside CommonJS,
// so the engine imports the implementation file directly. Same API as 'pdf-parse'.
declare module 'pdf-parse/lib/pdf-parse.js' {
  import pdfParse from 'pdf-parse'
  export default pdfParse
}
