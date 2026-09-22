import unittest
from io import BytesIO
from unittest.mock import Mock, patch
from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject
from pdf_support import extract_pdfs, PDFInputError
from core import check_documents, SelectedDecision


def fixture_pdf(lines, password=None):
    # 실제 PDF 바이트를 메모리에서 만들어 텍스트 추출 경로를 검사합니다.
    writer = PdfWriter()
    for line in lines:
        page = writer.add_blank_page(width=600, height=800)
        if line:
            font = DictionaryObject({NameObject('/Type'): NameObject('/Font'),
                NameObject('/Subtype'): NameObject('/Type1'), NameObject('/BaseFont'): NameObject('/Helvetica')})
            page[NameObject('/Resources')] = DictionaryObject({NameObject('/Font'): DictionaryObject({NameObject('/F1'): font})})
            stream = DecodedStreamObject()
            stream.set_data(f'BT /F1 12 Tf 50 700 Td ({line}) Tj ET'.encode('ascii'))
            page[NameObject('/Contents')] = stream
    if password:
        writer.encrypt(password)
    data = BytesIO()
    writer.write(data)
    return data.getvalue()


class PDFTests(unittest.TestCase):
    def test_multiple_pdfs_page_mapping(self):
        docs = [{'name': 'same.pdf', 'data': fixture_pdf(['Program begins in 2025 for all eligible applicants.', 'Payment is 1000 units for each eligible person.'])},
                {'name': 'same.pdf', 'data': fixture_pdf(['Other eligible groups are specified in this document.'])}]
        pages, failures, count = extract_pdfs(docs)
        self.assertEqual(count, 3)
        self.assertEqual(failures, [])
        self.assertEqual([p['id'] for p in pages], ['D1P1', 'D1P2', 'D2P1'])
        self.assertEqual(pages[1]['page_number'], 2)
        self.assertIn('1000', pages[1]['text'])

    def test_document_mode_never_searches_or_fetches(self):
        docs = [{'name': 'policy.pdf', 'data': fixture_pdf(['Program begins in 2025 for all eligible applicants.'])}]
        client = Mock()
        client.responses.parse.return_value.model_dump.return_value = {'status': 'completed'}
        client.responses.parse.return_value.output_parsed = SelectedDecision(
            verdict='참', confidence=90, explanation='문서의 시행 문구로 확인', scope='문서 범위',
            sufficient=True, time_verified=True, conflict=False, limitations=[], evidence=[dict(
                passage_id='D1P1_P1', relationship='지지', explanation='문서에 명시',
                publication_date='확인 불가', applicable_period='2025년')])
        with patch('core.fetch_page') as fetch:
            result = check_documents(client, '문서상 시행 시점은 2025년이다.', '2025-01-01', docs)
            fetch.assert_not_called()
        client.responses.create.assert_not_called()
        self.assertNotIn('tools', client.responses.parse.call_args.kwargs)
        self.assertIn('업로드한 PDF만', client.responses.parse.call_args.kwargs['input'][0]['content'])
        self.assertEqual(result['web_search_calls'], 0)
        self.assertEqual(result['verdict'], '참')
        self.assertEqual(result['sources'][0]['page_number'], 1)
        self.assertNotIn('url', result['sources'][0])

    def test_blank_pdf_returns_uncertain_without_api(self):
        client = Mock()
        result = check_documents(client, '문서의 정책 내용을 검증한다.', '2025-01-01',
                                 [{'name': 'scan.pdf', 'data': fixture_pdf([''])}])
        self.assertEqual(result['verdict'], '불확실')
        self.assertEqual(len(result['collection_failures']), 1)
        client.responses.create.assert_not_called()
        client.responses.parse.assert_not_called()

    def test_corrupt_encrypted_and_limits(self):
        for docs in [[], [{'name': 'broken.pdf', 'data': b'invalid'}],
                     [{'name': 'locked.pdf', 'data': fixture_pdf(['Policy statement'], 'private')}]]:
            with self.assertRaises(PDFInputError):
                extract_pdfs(docs)
        with patch('pdf_support.MAX_TEXT', 10):
            with self.assertRaises(PDFInputError):
                extract_pdfs([{'name': 'long.pdf', 'data': fixture_pdf(['A sufficiently long document text for this test.'])}])


if __name__ == '__main__':
    unittest.main()
