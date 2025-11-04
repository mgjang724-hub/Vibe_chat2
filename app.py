import os, io, re, json, hashlib
from datetime import datetime
from typing import Dict, Any

import streamlit as st
from openai import OpenAI

# ================== 전역 설정 및 LLM 초기화 ==================
st.set_page_config(page_title="바이브코딩 GAS 튜터", page_icon="🧩", layout="wide")

def _ensure_session_keys():
    if "corpus_text" not in st.session_state:
        st.session_state.corpus_text = ""
    if "is_admin" not in st.session_state:
        st.session_state.is_admin = False

_ensure_session_keys()  # <- 페이지 설정 직후, 어떤 UI 렌더 이전

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or st.secrets.get("OPENAI_API_KEY", "")
MODEL = os.getenv("OPENAI_MODEL") or st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")

# 관리자 보안 설정
ADMIN_PASSWORD   = st.secrets.get("ADMIN_PASSWORD", "")
ADMIN_LINK_TOKEN = st.secrets.get("ADMIN_LINK_TOKEN", "")  # 예: "vc-admin-2025"

# OpenAI 안전 초기화
if OPENAI_API_KEY:
    os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
    client = OpenAI()
else:
    client = None

# ================== 공통 유틸 ==================
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _rule_check(text: str) -> Dict[str, Any]:
    DISALLOWED = [
        ("로컬 프로그램 실행/OS 접근", r"(exe|msi|레지스트리|로컬 프로그램|시스템 파일)"),
        ("지속 실시간 소켓 서버", r"(웹소켓 서버|소켓 상시)"),
        ("하드웨어 직접 제어", r"(시리얼포트|GPIO|블루투스 장치 제어|라즈베리파이)"),
        ("대용량 미디어 처리", r"(영상 인코딩|STT 실시간 대규모|오디오 실시간 편집)"),
        ("장시간 동기 작업", r"(무한 루프|24시간 상시 실행|항시 구동)"),
    ]
    CAUTION = [
        ("대규모 크롤링", r"(대량 크롤링|수천 페이지)"),
        ("외부 OAuth 복잡", r"(카카오|네이버|슬랙|노션 OAuth)"),
        ("대량 메일/알림", r"(수천명 메일|대량 푸시)"),
    ]
    viol, caut = [], []
    for name, pat in DISALLOWED:
        if re.search(pat, text, re.I): viol.append(name)
    for name, pat in CAUTION:
        if re.search(pat, text, re.I): caut.append(name)
    score = 0.8 - 0.3*bool(viol) - 0.1*len(caut)
    return {"score": max(0.0, min(1.0, score)), "violations": viol, "cautions": caut}

def _read_file_to_text(upload) -> str:
    name = upload.name.lower()
    data = upload.read()
    if name.endswith(".pdf"):
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(data))
            return "\n".join([(p.extract_text() or "") for p in reader.pages])
        except Exception as e:
            return f"[PDF 파싱 실패] {e}"
    else:
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return data.decode("cp949", errors="ignore")

def _call_openai(system: str, user: str) -> str:
    if not client:
        return json.dumps({"error":"OPENAI_API_KEY 필요"})
    resp = client.chat.completions.create(
        model=MODEL,
        temperature=0.15,
        messages=[{"role":"system","content":system},
                  {"role":"user","content":user}]
    )
    return resp.choices[0].message.content.strip()

# ================== 관리자 포털 노출 조건 ==================
def _is_admin_link() -> bool:
    # 안전: 항상 experimental_get_query_params 사용
    try:
        qp = st.experimental_get_query_params() or {}
    except Exception:
        qp = {}
    token_param = qp.get("admin")
    token = ""
    if isinstance(token_param, list) and token_param:
        token = token_param[0]
    elif isinstance(token_param, str):
        token = token_param
    return bool(ADMIN_LINK_TOKEN and token and token == ADMIN_LINK_TOKEN)


def _ensure_session_keys():
    if "corpus_text" not in st.session_state:
        st.session_state.corpus_text = ""  # 관리자 업로드로 채워짐
    if "is_admin" not in st.session_state:
        st.session_state.is_admin = False

_ensure_session_keys()

# ================== 헤더(UI 최소화) ==================
st.markdown(
    """
    <style>
      /* 사이드바 기본 텍스트 정리 */
      section[data-testid="stSidebar"] .stMarkdown, 
      section[data-testid="stSidebar"] .stCaption { font-size: 0.92rem; }
      /* 버튼 간격 */
      .stButton>button { width:100%; }
    </style>
    """, unsafe_allow_html=True
)

st.title("바이브코딩 Apps Script 튜터")
st.caption("입력: 제목·설명, 주 사용자, 구현 기능 → 출력: Apps Script 가능성, 보완 제안, 블루프린트, 예시 코드, PRD")

# ================== 일반 사용자용 사이드바(상태만 표시) ==================
with st.sidebar:
    st.subheader("상태")
    st.write(f"LLM: `{MODEL}`")
    st.write("버전: 1.2")
    # 관리자 포털은 노출하지 않음

# ================== 메인: 사용자 UX ==================
# 상단 도움말 컴팩트
with st.expander("사용 방법", expanded=False):
    st.markdown(
        "- 1) 제목과 설명, 주 사용자, 기능을 입력한다.\n"
        "- 2) 버튼을 누르면 Apps Script로 구현 가능한 형태로 재설계와 PRD를 생성한다.\n"
        "- 3) 블루프린트 JSON과 PRD를 저장해 구현에 활용한다."
    )

# 입력 카드
with st.form("idea_form", clear_on_submit=False):
    st.markdown("#### 아이디어 입력")
    c1, c2 = st.columns([2,1])
    with c1:
        title = st.text_input("제목", placeholder="예) 학급 공지·과제 리마인더 자동화")
    with c2:
        users = st.text_input("주 사용자", placeholder="예) 담임교사, 학생, 행정실")
    desc = st.text_area("설명", placeholder="아이디어의 배경과 목적", height=120)
    features = st.text_area(
        "구현하려는 기능",
        placeholder="- 주간 리마인더 메일 발송\n- Google Form 응답 자동 집계\n- 승인/반려 워크플로",
        height=160
    )
    left, right = st.columns([1,1])
    with left:
        submitted = st.form_submit_button("가능성 평가 + 보완 제안 + PRD 생성", type="primary")
    with right:
        st.form_submit_button("입력 초기화")

# 결과 탭
if submitted:
    idea_block = f"제목: {title}\n설명: {desc}\n주 사용자: {users}\n기능:\n{features}"
    rc = _rule_check(idea_block)

    SYSTEM = """역할: 당신은 'Google Apps Script 설계 조언가'다.
목표:
- 입력된 아이디어를 Apps Script 중심으로 재설계한다.
- 불가능/부적합 요소는 대체 경로로 수정·보완한다.
- 결과는 JSON 한 개만 출력한다. 한국어로 간결하고 구조화한다.
출력 JSON 스키마:
{
  "feasibility": {"score": 0~1, "summary": "한 줄 요약"},
  "adjustments": ["보완/범위 조정 제안…"],
  "blueprint": {
    "data_schema": [{"sheet":"이름","columns":["A","B","..."]}],
    "services": ["Sheets","Drive","UrlFetchApp"],
    "scopes": ["https://..."],
    "endpoints": [{"path":"/hook","method":"POST","fields":["..."]}],
    "triggers": [{"type":"time","every":"day 09:00"}],
    "kpis": ["예: 전송 성공률 99%","다운로드→사용률 30%+"]
  },
  "gas_snippets": [{"title":"핵심","code":"```js\\nfunction doPost(e){/*...*/}\\n```"}],
  "risks": ["quota","auth","pii"],
  "prd": "마크다운 PRD 본문",
  "next_steps": ["1.","2.","3."]
}
지침:
- Sheets 테이블 구조는 열 이름을 명시한다.
- WebApp(doGet/doPost)와 트리거가 필요하면 구체적으로 제안한다.
- 예시 Apps Script 코드는 60줄 내 핵심만 제시한다.
- 개인정보/권한/쿼터 리스크를 명시한다.
- 제공된 '지식'이 있으면 우선 반영하되, 없으면 일반 지식으로 추론하고 '추정'임을 표시한다.
"""

    user_prompt = f"""
[아이디어]
{idea_block}

[룰 체크]
점수: {rc['score']:.2f}
불가 패턴: {', '.join(rc['violations']) or '없음'}
주의 패턴: {', '.join(rc['cautions']) or '없음'}

[사용 가능한 빌딩블록]
- Google Sheets 저장/조회
- Apps Script WebApp(doGet/doPost)
- Time-driven 트리거
- UrlFetchApp 외부 API 연동
- GmailApp 알림
- Drive/Docs/Slides 자동화
- PropertiesService 설정/토큰 저장

[권장 스코프 힌트]
{json.dumps({
    "Sheets":"https://www.googleapis.com/auth/spreadsheets",
    "Drive":"https://www.googleapis.com/auth/drive",
    "Gmail":"https://www.googleapis.com/auth/gmail.send",
    "Calendar":"https://www.googleapis.com/auth/calendar"
}, ensure_ascii=False)}

[지식(업로드 자산 스냅샷)]
{(st.session_state.corpus_text[:8000] if st.session_state.corpus_text else "(지식 없음)")}
JSON만 출력하라.
"""

    with st.spinner("생성 중"):
        raw = _call_openai(SYSTEM, user_prompt)

    # JSON 파싱
    try:
        data = json.loads(raw)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", raw)
        data = json.loads(m.group(0)) if m else {"error":"JSON 파싱 실패", "raw":raw}

    t1, t2, t3 = st.tabs(["요약", "설계·코드", "PRD"])

    with t1:
        colA, colB = st.columns([1,1])
        with colA:
            score = float(data.get("feasibility", {}).get("score", rc["score"]))
            st.metric("Apps Script 가능성", f"{score:.2f}")
        with colB:
            st.write(data.get("feasibility", {}).get("summary",""))

        st.markdown("**보완·범위 조정 제안**")
        for it in data.get("adjustments", []):
            st.write("• " + it)

        with st.expander("규칙 기반 1차 판정 세부"):
            st.json(rc)

    with t2:
        st.markdown("#### 설계 블루프린트(JSON)")
        blueprint = data.get("blueprint", {})
        st.json(blueprint)
        st.download_button(
            "블루프린트 JSON 다운로드",
            json.dumps(blueprint, ensure_ascii=False, indent=2).encode("utf-8"),
            file_name="blueprint.json"
        )

        st.markdown("#### 예시 Apps Script 스니펫")
        for sn in data.get("gas_snippets", []):
            code = sn.get("code","").replace("```js","").replace("```javascript","").replace("```","")
            st.markdown(f"**{sn.get('title','스니펫')}**")
            st.code(code, language="javascript")

        st.markdown("#### 리스크")
        st.write(data.get("risks", []))

    with t3:
        prd_md = data.get("prd","")
        if prd_md:
            st.markdown("#### PRD 초안")
            st.markdown(prd_md)
            st.download_button("PRD.md 다운로드", prd_md.encode("utf-8"), file_name="PRD.md")
        else:
            st.info("PRD 생성 결과가 비어 있습니다.")

# ================== 관리자 포털 ==================
# 일반 사용자에게는 전혀 노출하지 않음. admin 링크 파라미터가 맞을 때만 등장.
if _is_admin_link():
    st.markdown("---")
    st.markdown("##### 관리자 포털")
    # 로그인 상태 여부
    if not st.session_state.is_admin:
        with st.form("admin_login"):
            pwd = st.text_input("관리자 비밀번호", type="password")
            ok = st.form_submit_button("로그인")
            if ok:
                if ADMIN_PASSWORD and _sha256(pwd) == _sha256(ADMIN_PASSWORD):
                    st.session_state.is_admin = True
                    st.success("관리자 로그인")
                    st.rerun()
                else:
                    st.error("인증 실패")
    else:
        st.success("관리자 모드")
        st.caption("연수 원고·레퍼런스 자산을 업로드하면 답변 품질이 향상됩니다.")
        uploads = st.file_uploader("PDF/TXT/MD 업로드", type=["pdf","txt","md"], accept_multiple_files=True)
        if uploads:
            texts = []
            for up in uploads:
                texts.append(_read_file_to_text(up))
            st.session_state.corpus_text = "\n\n".join(texts)
            st.success(f"문서 {len(uploads)}개 로드 완료")
        cols = st.columns([1,1,1])
        with cols[0]:
            if st.button("자산 초기화"):
                st.session_state.corpus_text = ""
                st.warning("지식 초기화 완료")
        with cols[1]:
            st.download_button(
                "현재 자산 다운로드",
                (st.session_state.corpus_text or "").encode("utf-8"),
                file_name="corpus.txt"
            )
        with cols[2]:
            if st.button("로그아웃"):
                st.session_state.is_admin = False
                st.rerun()
