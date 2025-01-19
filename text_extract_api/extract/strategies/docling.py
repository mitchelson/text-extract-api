import tempfile

from typing import Optional
from docling_core.types.doc.document import DoclingDocument

from docling_parse.docling_parse import pdf_parser_v2

from text_extract_api.extract.strategies.strategy import Strategy
from text_extract_api.files.file_formats.file_format import FileFormat

class DoclingStrategy(Strategy):

    def __init__(self):
        super().__init__()
        self._document: Optional[DoclingDocument] = None
        self._current_file_format: Optional[FileFormat] = None
        self._parser = pdf_parser_v2("error")  # @todo move it to construct


    @property
    def document(self) -> Optional[DoclingDocument]:
        """Access the current DoclingDocument instance"""
        return self._document

    @classmethod
    def name(cls) -> str:
        return "docling"

def extract_text(self, file_format: FileFormat, language: str = 'en') -> str:


    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temp_file:
        temp_file.write(image.binary)
        temp_filename = temp_file.name

        doc_file = temp_filename
        doc_key = f"key={file_format.filename}"

    success = self._parser.load_document(doc_key, doc_file)

    num_pages = self._parser.number_of_pages(doc_key)

    for page in range(0, num_pages):

        json_doc = self._parser.parse_pdf_from_key_on_page(doc_key, page)

        if "pages" not in json_doc:
            continue

        json_page = json_doc["pages"][0]
        print(json_page)


    self._parser.unload_document(doc_key)
