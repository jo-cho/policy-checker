import hmac
import json
import os
import time
from datetime import datetime
from zoneinfo import ZoneInfo
import streamlit as st
from openai import OpenAI
from core import check_claim, DOMAINS, error_diagnostic, normalize_domain

st.set_page_config(page_title='정책 팩트체크', page_icon='🔎', layout='centered')


def setting(name, default=''):
    try:
        return st.secrets.get(name, os.getenv(name, default))
    except FileNotFoundError:
        return os.getenv(name, default)


st.caption('POLICY FACT CHECK · 웹 근거 검증')
st.title('경제정책, 근거로 확인하세요')
st.write('주장을 입력하면 선택한 검색 범위에서 원문을 찾아 참, 거짓, 불확실로 판정합니다.')
with st.sidebar:
    st.subheader('판정 기준')
    st.write('🟢 참: 증거로 입증됨\n\n🔴 거짓: 증거로 반박됨\n\n🟡 불확실: 충분한 증거 없음')
    st.caption('신뢰도는 LLM의 자기평가입니다. 통계적으로 검증된 정답 확률이 아닙니다.')
    st.caption('열람 가능한 HTML·텍스트 본문만 판정에 사용합니다.')

password = setting('APP_PASSWORD')
if password:
    entered = st.text_input('이용 비밀번호', type='password')
    if not hmac.compare_digest(entered.encode(), password.encode()):
        st.info('비밀번호를 입력하면 사용할 수 있습니다.')
        st.stop()

def sources_changed():
    st.session_state.pop('result', None)


def add_source():
    try:
        domain = normalize_domain(st.session_state.get('new_source', ''))
        selected = st.session_state.active_domains
        if domain in selected:
            st.session_state.source_notice = '이미 선택한 출처입니다.'
            return
        if len(selected) >= 100:
            st.session_state.source_notice = '허용 출처는 최대 100개까지 선택할 수 있습니다.'
            return
        if domain not in st.session_state.domain_options:
            st.session_state.domain_options = [*st.session_state.domain_options, domain]
        st.session_state.active_domains = [*selected, domain]
        st.session_state.new_source = ''
        st.session_state.source_notice = domain + ' 추가됨'
        sources_changed()
    except ValueError as exc:
        st.session_state.source_notice = str(exc)


def reset_sources():
    st.session_state.domain_options = list(DOMAINS)
    st.session_state.active_domains = list(DOMAINS)
    st.session_state.all_web = False
    st.session_state.source_notice = '정부·법령 기본 출처 목록으로 복원했습니다.'
    sources_changed()


if 'active_domains' not in st.session_state:
    st.session_state.active_domains = list(DOMAINS)
    st.session_state.domain_options = list(DOMAINS)

with st.sidebar:
    judgement_mode = st.radio('판정 방식', ['균형', '엄격'], key='judgement_mode',
                              on_change=sources_changed, horizontal=True)
    st.caption('균형: 핵심 사실에 충분한 직접 근거가 있으면 판정합니다. 엄격: 모든 핵심 조건과 적용 시점을 보수적으로 확인합니다.')
    st.subheader('검색 범위')
    all_web = st.toggle('전체 웹 검색', key='all_web', on_change=sources_changed)
    st.caption('기본값은 정부·법령 목록입니다. 전체 웹 검색을 켜면 아래 목록 제한을 적용하지 않습니다.')
    st.caption('선택한 주소의 ×를 누르면 제거됩니다. 하위 도메인도 포함하며, 변경은 현재 세션에만 적용됩니다.')
    selected_domains = st.multiselect('검색에 사용할 출처',
        options=st.session_state.domain_options, key='active_domains',
        on_change=sources_changed, disabled=all_web)
    st.text_input('출처 추가', placeholder='예: reuters.com', key='new_source', disabled=all_web)
    st.button('출처 추가하기', on_click=add_source, disabled=all_web)
    st.button('기본 목록 복원', on_click=reset_sources)
    st.caption('언론·연구기관 등 공개 웹사이트를 추가할 수 있습니다. URL을 넣으면 도메인만 추가합니다.')
    if st.session_state.get('source_notice'):
        st.caption(st.session_state.source_notice)
    if not all_web and not selected_domains:
        st.warning('검증하려면 출처를 1개 이상 선택해 주세요.')

def clear_api_key():
    st.session_state['user_api_key'] = ''


with st.sidebar:
    st.subheader('OpenAI API 키')
    key = st.text_input('API 키 입력', type='password', key='user_api_key',
                        placeholder='sk-…').strip()
    st.button('입력한 키 지우기', on_click=clear_api_key)
    st.caption('키는 현재 세션에서만 사용하며 파일에 저장하지 않습니다. 요청 시 앱 서버를 거쳐 OpenAI로 전송됩니다. 입력한 키의 계정에 API 요금이 발생합니다.')

with st.form('claim_form'):
    claim = st.text_area('검증할 주장', max_chars=1500, height=130,
                         placeholder='정책명, 적용 연도, 대상, 금액을 포함해 한 가지 주장으로 입력하세요.')
    as_of = st.date_input('판정 기준일', value=datetime.now(ZoneInfo('Asia/Seoul')).date())
    st.caption('입력한 주장과 수집한 문서가 OpenAI API로 전송됩니다.')
    submitted = st.form_submit_button('근거로 검증하기', type='primary')

if submitted:
    st.session_state.pop('result', None)
    if len(claim.strip()) < 10:
        st.warning('10자 이상의 구체적인 주장을 입력해 주세요.')
    elif not all_web and not selected_domains:
        st.error('허용 출처를 1개 이상 선택해 주세요.')
    elif not key:
        st.error('왼쪽 사이드바에 OpenAI API 키를 입력해 주세요.')
    elif time.time() - st.session_state.get('last_request', 0) < 30:
        st.warning('연속 요청은 30초 간격으로 가능합니다.')
    else:
        st.session_state.last_request = time.time()
        stage = ['API 클라이언트 준비']
        progress_label = st.empty()

        def show_progress(value):
            stage[0] = value
            progress_label.caption('현재 단계: ' + value)

        try:
            with st.spinner('웹 근거 검색 → 원문 확인 → 판정 중입니다…'):
                with OpenAI(api_key=key, timeout=90, max_retries=1) as client:
                    st.session_state.result = check_claim(
                        client, claim.strip(), as_of.isoformat(), setting('OPENAI_MODEL', 'gpt-4.1'),
                        on_progress=show_progress, domains=selected_domains, all_web=all_web, judgement_mode=judgement_mode)
        except Exception as exc:
            message, detail = error_diagnostic(exc, stage[0])
            st.error(message)
            st.caption('오류 진단 · 아래 정보를 복사해 전달해 주세요. API 키는 보내지 마세요.')
            st.json(detail)
        finally:
            progress_label.empty()

if 'result' in st.session_state:
    r = st.session_state.result
    st.divider()
    st.text('검증한 주장: ' + r['claim'])
    a, b = st.columns(2)
    a.metric('판정', r['verdict'])
    b.metric('LLM 판정 신뢰도', f"{r['confidence']}%" if r['confidence'] is not None else '산출 안 함')
    st.caption('선택된 판정에 대한 자기평가이며, 주장이 참일 확률이 아닙니다.')
    st.text(r['explanation'])
    st.caption(f"판정 방식: {r.get('judgement_mode', '균형')} · 판정 경로: {r.get('decision_origin', 'LLM 판정')}")
    if r['verdict'] == '불확실':
        st.info(f"검색 후보 {r.get('candidate_count', 0)}개 중 본문 확보 {r.get('collected_count', 0)}개. "
                '본문 확보 실패인지, 근거 내용이 부족한지 아래 설명과 수집 내역을 확인해 주세요.')
    st.caption('판정 범위: ' + r['scope'])
    st.caption(f"기준일 {r['as_of']} · 확인 시각 {r['checked_at']} · 모델 {r['model']}")
    sources = {s['id']: s for s in r['sources']}
    st.subheader('판정에 사용한 근거')
    if not r['evidence']:
        st.info('확정 판정에 사용할 검증된 인용 근거가 없습니다.')
    for e in r['evidence']:
        s = sources[e['source_id']]
        with st.container(border=True):
            st.text(f"[{s['id']}] {s['title']} · {e['relationship']}")
            st.text('“' + e['quote'] + '”')
            st.text(e['explanation'])
            st.caption(f"발행일: {e['publication_date']} · 적용 시점: {e['applicable_period']}")
            st.link_button('원문 열기', s['url'])
    if r['limitations']:
        st.subheader('확인되지 않은 부분')
        for item in r['limitations']:
            st.text('• ' + item)
    with st.expander('검색 범위 및 웹 검색 실행 내역'):
        st.text('검색 범위: ' + r.get('search_scope', '선택한 출처'))
        st.text(f"OpenAI 웹 검색 도구 호출: {r.get('web_search_calls', 0)}회")
        if r.get('search_scope') != '전체 웹':
            st.text('\n'.join(r.get('allowed_domains', [])))
    with st.expander('수집 내역'):
        st.caption('수집 성공은 해당 문서를 판정 근거로 채택했다는 의미가 아닙니다.')
        for s in r['sources']:
            st.link_button(f"[{s['id']}] {s['title']}", s['url'])
        for failure in r['collection_failures']:
            st.text(f"{failure['url']} — {failure['reason']}")
    st.download_button('결과 JSON 내려받기', json.dumps(r, ensure_ascii=False, indent=2),
                       file_name='policy-check.json', mime='application/json')
