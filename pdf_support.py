from io import BytesIO
from pypdf import PdfReader

MAX_FILES = 5
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_PAGES = 100
MAX_TEXT = 150_000


class PDFInputError(ValueError):
    pass


def extract_pdfs(documents):
    if not 1 <= len(documents) <= MAX_FILES:
        raise PDFInputError('PDF를 1개 이상 5개 이하로 올려 주세요.')
    pages, failures = [], []
    total_pages = total_text = 0
    for index, document in enumerate(documents, 1):
        name, data = document['name'], document['data']
        if len(data) > MAX_FILE_BYTES:
            raise PDFInputError(f'{name}: 파일당 최대 10MB까지 지원합니다.')
        if not data.startswith(b'%PDF-'):
            raise PDFInputError(f'{name}: 올바른 PDF 파일이 아닙니다.')
        try:
            reader = PdfReader(BytesIO(data))
            if reader.is_encrypted and not reader.decrypt(''):
                raise PDFInputError(f'{name}: 비밀번호를 해제한 PDF를 올려 주세요.')
            total_pages += len(reader.pages)
            if total_pages > MAX_PAGES:
                raise PDFInputError('전체 PDF가 합계 100쪽을 넘습니다. 문서를 나누어 올려 주세요.')
            for number, page in enumerate(reader.pages, 1):
                try:
                    contents = page.get_contents()
                    if contents is not None and len(contents.get_data()) > 5_000_000:
                        raise ValueError('페이지 크기 제한 초과')
                    text = ' '.join((page.extract_text() or '').split())
                except Exception:
                    failures.append({'file_name': name, 'page_number': number, 'reason': '페이지 텍스트 추출 실패'})
                    continue
                if len(text.strip()) < 15:
                    failures.append({'file_name': name, 'page_number': number,
                                     'reason': '텍스트가 없거나 너무 짧음: 스캔본은 OCR 처리 후 업로드하세요.'})
                    continue
                total_text += len(text)
                if total_text > MAX_TEXT:
                    raise PDFInputError('추출 본문이 15만 자를 넘습니다. 문서를 나누어 올려 주세요.')
                pages.append({'id': f'D{index}P{number}', 'title': f'{name} · {number}쪽',
                              'file_id': f'F{index}', 'file_name': name, 'page_number': number,
                              'source_type': 'pdf', 'text': text})
        except PDFInputError:
            raise
        except Exception as exc:
            raise PDFInputError(f'{name}: PDF를 읽을 수 없습니다. 파일 손상 또는 암호화를 확인해 주세요.') from exc
    return pages, failures, total_pages
