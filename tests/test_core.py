import unittest
from unittest.mock import Mock, patch
from core import allowed_url, SafeRedirect, Decision, gate, fetch_page, candidates, check_claim


class EvidenceSafetyTests(unittest.TestCase):
    def setUp(self):
        self.pages = [{'id': 'S1', 'url': 'https://www.law.go.kr/a',
                       'text': '이 제도는 2025년 1월 1일부터 시행하며 모든 대상자에게 적용한다.'}]
        self.data = dict(verdict='참', confidence=91, explanation='S1에 의해 확인됨',
                         scope='제도 시행', sufficient=True, time_verified=True, conflict=False,
                         evidence=[dict(source_id='S1', quote=self.pages[0]['text'],
                                        relationship='지지', explanation='직접 입증',
                                        publication_date='2024-12-01', applicable_period='2025-01-01 이후')],
                         limitations=[])

    def test_domain_spoofing(self):
        for url in ['https://law.go.kr.evil.com/a', 'https://evil-law.go.kr/a',
                    'https://law.go.kr@evil.com', 'http://law.go.kr',
                    'https://law.go.kr:8443', 'https://127.0.0.1',
                    'https://law.go.kr:bad', 'https://news.example.com']:
            self.assertFalse(allowed_url(url), url)
        self.assertTrue(allowed_url('https://www.law.go.kr/법령'))

    def test_redirect_blocked(self):
        with self.assertRaises(ValueError):
            SafeRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.com')

    def test_valid_quote(self):
        self.assertEqual(gate(Decision(**self.data), self.pages)['verdict'], '참')

    def test_invented_quote(self):
        self.data['evidence'][0]['quote'] = '본문 어디에도 없는 완전히 지어낸 인용 문장입니다.'
        result = gate(Decision(**self.data), self.pages)
        self.assertEqual(result['verdict'], '불확실')
        self.assertIsNone(result['confidence'])
        self.assertEqual(result['evidence'], [])

    def test_unknown_source(self):
        self.data['evidence'][0]['source_id'] = 'S99'
        self.assertEqual(gate(Decision(**self.data), self.pages)['verdict'], '불확실')

    def test_missing_time_conflict_or_insufficient(self):
        for field, value in [('time_verified', False), ('conflict', True), ('sufficient', False)]:
            data = {**self.data, field: value}
            self.assertEqual(gate(Decision(**data), self.pages)['verdict'], '불확실')

    def test_missing_or_wrong_direction(self):
        self.data['verdict'] = '거짓'
        self.assertEqual(gate(Decision(**self.data), self.pages)['verdict'], '불확실')
        self.data['evidence'] = []
        self.assertEqual(gate(Decision(**self.data), self.pages)['verdict'], '불확실')

    def test_no_source_is_not_false(self):
        client = Mock()
        client.responses.create.return_value.model_dump.return_value = {'output': []}
        result = check_claim(client, '검증할 충분히 긴 정책 주장', '2025-01-01')
        self.assertEqual(result['verdict'], '불확실')
        self.assertIsNone(result['confidence'])
        client.responses.parse.assert_not_called()

    def test_generated_urls_are_not_sources(self):
        response = Mock()
        response.model_dump.return_value = {'output': [{'content': [
            {'text': 'https://law.go.kr/invented', 'annotations': []}]}]}
        self.assertEqual(candidates(response), [])

    def test_disallowed_url_never_fetched(self):
        with patch('core.build_opener') as opener:
            self.assertIsNone(fetch_page({'url': 'https://example.com'})[0])
            opener.assert_not_called()


if __name__ == '__main__':
    unittest.main()
