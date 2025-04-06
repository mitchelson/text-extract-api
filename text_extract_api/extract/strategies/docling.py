from text_extract_api.extract.extract_result import ExtractResult
from text_extract_api.extract.strategies.strategy import Strategy
from text_extract_api.files.file_formats import FileFormat, PdfFileFormat
from docling_core.types.doc.document import DoclingDocument  # Assuming a compatible Docling library or module
import tempfile


class DoclingStrategy(Strategy):
    """
    Extraction strategy for processing PDF documents using Docling.
    """

    def extract_text(self, file_format: FileFormat, language: str = 'en') -> ExtractResult:
        """
        Extracts text from a PDF file using Docling and returns an ExtractResult.

        :param file_format: Instance of FileFormat (only supports PdfFileFormat).
        :param language: Language of the text (default is 'en').
        :return: ExtractResult containing the extracted DoclingDocument and metadata.
        """
        if not isinstance(file_format, PdfFileFormat):
            raise ValueError("DoclingStrategy only supports PdfFileFormat.")

        # Save file content to a temporary file
        temp_file_path = self._save_to_temp_file(file_format)

        # Convert the document using Docling
        docling_document = self._convert_to_docling(temp_file_path)

        print(docling_document)
        # Return the result wrapped in ExtractResult
        return ExtractResult(value=docling_document, text_gatherer=self.text_gatherer)

    def text_gatherer(self, docling_document: DoclingDocument) -> str:
        """
        Gathers text content from a DoclingDocument in markdown format.

        :param docling_document: Instance of DoclingDocument.
        :return: Text content in markdown format.
        """
        return docling_document.to_markdown()

    def _convert_to_docling(self, file_path: str) -> DoclingDocument:
        """
        Converts a PDF file into a DoclingDocument instance.

        :param file_path: Path to the PDF file to be converted.
        :return: DoclingDocument instance.
        """
        # Placeholder for actual conversion logic using the Docling API
        try:
            docling_document = DoclingDocument.from_file(file_path)
            return docling_document
        except Exception as e:
            raise RuntimeError(f"Failed to convert document using Docling: {e}")

    def _save_to_temp_file(self, file_format: FileFormat) -> str:
        """
        Saves the content of a FileFormat instance to a temporary file.

        :param file_format: Instance of FileFormat.
        :return: Path to the temporary file containing the file content.
        """
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
            temp_file.write(file_format.get_content())  # Assuming get_content provides binary content
            return temp_file.name
