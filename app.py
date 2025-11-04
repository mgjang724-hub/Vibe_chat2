import os, io, re, json, hashlib
from datetime import datetime
from typing import Dict, Any

import streamlit as st
# pypdf를 사용하려면 미리 설치 필요: pip install pypdf
try:
    from pypdf import PdfReader
except ImportError:
    st.warning("PDF 파싱을 위해 'pypdf' 라이브러리가 필요합니다. 'pip install pypdf'를 실행해주세요.")
    
# openai 라이브러리가 필요: pip install openai
try:
    from openai import OpenAI
except ImportError:
    st.error("OpenAI 라이브러리가 필요합니다. 'pip install openai'를 실행해주세요.")
    # 임시 클래스로 대체하여 코드 실행은 가능하게 합니다.
    class DummyClient:
        def __init__(self): pass
        def chat(self): pass
    client = DummyClient()


# ================== 전역 설정 및 LLM 초기화 ==================
st.set_page_config(page_title="바이브코딩 GAS 튜터", page_icon="🧩", layout="wide")

def _ensure_session_keys():
    if "corpus_text" not in st.session_state:
        st.session_state.corpus_text = ""
    if "is_admin" not in st.session_state:
        st.session_state.is_admin = False
    if "last_result" not in st.session_state:
        st.session_state.last_result = None

_ensure_session_keys()

# 환경 변수 또는 secrets에서 API 키와 모델 로드
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or st.secrets.get("OPENAI_API_KEY", "")
MODEL = os.getenv("OPENAI_MODEL") or st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")

# 관리자 보안 설정
ADMIN_PASSWORD    = st.secrets.get("ADMIN_PASSWORD", "")
ADMIN_LINK_TOKEN = st.secrets.get("ADMIN_LINK_TOKEN", "")  # 예: "vc-admin-2025"

# OpenAI 안전 초기화
if OPENAI_API_KEY:
    os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
    try:
        client = OpenAI()
    except Exception as e:
        st.error(f"OpenAI 클라이언트 초기화 실패: {e}")
        client = None
else:
    client = None

# ================== 공통 유틸 ==================
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def _rule_check(text: str) -> Dict[str, Any]:
    """Apps Script 환경에서 부적합한 아이디어를 1차적으로 판정하는 규칙"""
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
    
    # 규칙 점수 계산: 불가능 패턴 0.3점 감점, 주의 패턴 0.1점 감점
    score = 0.8 - 0.3*bool(viol) - 0.1*len(caut)
    return {"score": max(0.0, min(1.0, score)), "violations": viol, "cautions": caut}

def _read_file_to_text(upload) -> str:
    """업로드된 파일을 텍스트로 읽는 함수 (PDF 포함)"""
    name = upload.name.lower()
    data = upload.read()
    if name.endswith(".pdf"):
        try:
            # pypdf가 import 되어 있어야 함
            reader = PdfReader(io.BytesIO(data))
            return "\n".join([(p.extract_text() or "") for p in reader.pages])
        except NameError:
             return "[PDF 파싱 실패] 'pypdf' 라이브러리를 찾을 수 없습니다."
        except Exception as e:
            return f"[PDF 파싱 실패] {e}"
    else:
        try:
            return data.decode("utf-8", errors="ignore")
        except Exception:
            return data.decode("cp949", errors="ignore")

def _call_openai(system: str, user: str) -> str | None:
    """OpenAI API 호출 유틸리티"""
    if not client:
        st.error("OPENAI_API_KEY 미설정 또는 클라이언트 초기화 실패.")
        return None
    try:
        with st.spinner("LLM 호출 중"):
            resp = client.chat.completions.create(
                model=MODEL,
                temperature=0.15,
                messages=[
                    {"role":"system","content":system},
                    {"role":"user","content":user}
                ],
                timeout=60,
            )
        content = resp.choices[0].message.content
        if not content:
            st.error("LLM 응답이 비어 있음.")
            return None
        return content.strip()
    except Exception as e:
        st.error(f"LLM 호출 실패: {type(e).__name__}: {e}")
        return None

# ================== 관리자 포털 노출 조건 ==================
def _is_admin_link() -> bool:
    """관리자 전용 링크인지 판별"""
    try:
        qp = st.query_params or {}   # 최신 API
    except Exception:
        qp = {}
    token = ""
    if isinstance(qp, dict):
        token_value = qp.get("admin")
        if isinstance(token_value, list) and token_value:
            token = token_value[0]
        elif isinstance(token_value, str):
            token = token_value
    return bool(ADMIN_LINK_TOKEN and token and token == ADMIN_LINK_TOKEN)


# ================== 스타일 (디자인 감각 반영) ==================
st.markdown(
    """
    <style>
      .stButton>button { width:100%; }
      /* LLM 모델명 (GPT-4o-mini 등)을 뱃지처럼 보이게 */
      .llm-badge {
          display: inline-block;
          padding: 0.2em 0.4em;
          font-size: 0.8em;
          font-weight: 600;
          line-height: 1;
          color: #1a1a1a;
          text-align: center;
          white-space: nowrap;
          vertical-align: middle;
          background-color: #f0f2f6; /* 밝은 회색 */
          border-radius: 0.35rem;
          margin-left: 5px;
      }
      /* 제목과 부제목 간의 여백 확보 */
      h1 { margin-bottom: 0.5rem; }
      .stCaption { margin-top: -0.5rem; margin-bottom: 1rem; }
    </style>
    """, unsafe_allow_html=True
)

# ================== 상수 프롬프트(SYSTEM) ==================
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

# ================== 헤더 및 사이드바 (가독성 개선) ==================
st.title("🧩 바이브코딩 Apps Script 튜터")
st.caption("입력: 제목·설명, 주 사용자, 구현 기능 → 출력: Apps Script 가능성, 보완 제안, 블루프린트, 예시 코드, PRD")

with st.sidebar:
    st.subheader("🛠️ 상태 및 환경")
    st.divider() # 시각적 분리
    # LLM 모델명을 뱃지 스타일로 출력
    st.markdown(f"**LLM 모델** : <span class='llm-badge'>{MODEL}</span>", unsafe_allow_html=True)
    st.write("API 키 감지:", "예" if OPENAI_API_KEY else "아니오")
    st.write("지식 자산 길이:", f"{len(st.session_state.corpus_text):,} 자")
    st.divider()


# ================== 사용자 폼 ==================
with st.expander("사용 방법", expanded=False):
    st.markdown(
        "- 1) 제목·설명, 주 사용자, 기능을 입력.\n"
        "- 2) 버튼 클릭 시 GAS 가능성 평가 + PRD 자동 생성.\n"
        "- 3) 블루프린트와 PRD를 다운로드."
    )

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
    
    # 버튼 배치: 핵심 액션 강조
    col_btn1, col_btn2 = st.columns([2,1]) # 생성 버튼에 더 많은 공간 할애
    with col_btn1:
        do_generate = st.form_submit_button("가능성 평가 + 보완 제안 + PRD 생성", type="primary", use_container_width=True)
    with col_btn2:
        # 리셋 버튼은 보조적인 역할
        do_reset = st.form_submit_button("입력 초기화", use_container_width=True)

if do_reset:
    st.session_state.last_result = None
    st.rerun()

if do_generate:
    if not title or not users or not (desc or features):
        st.warning("제목, 주 사용자, 설명/기능 중 최소 한 항목은 채워야 합니다.")
        st.stop()

    idea_block = f"제목: {title}\n설명: {desc}\n주 사용자: {users}\n기능:\n{features}"
    rc = _rule_check(idea_block)

    with st.status("분석 파이프라인 실행 중", expanded=True) as status:
        
        # 1/3 규칙 기반 1차 판정 (시각화 강화)
        st.write("1/3 **규칙 기반 1차 판정**")
        if rc['violations']:
            st.error(f"❌ **[실현 불가]** Apps Script 환경에서 금지된 패턴 감지: **{', '.join(rc['violations'])}**")
        elif rc['cautions']:
            st.warning(f"⚠️ **[주의 필요]** 대규모 작업/복잡한 인증 등 쿼터/권한 이슈가 예상되는 패턴 감지: {', '.join(rc['cautions'])}")
        else:
            st.success("✅ **[적합]** Apps Script 구현에 매우 적합한 아이디어입니다.")
        st.caption(f"규칙 기반 점수: **{rc['score']:.2f}** (0.00 ~ 1.00)")
        st.divider() # 시각적 구분

        st.write("2/3 LLM 요청 전송")
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
        raw = _call_openai(SYSTEM, user_prompt)
        if raw is None:
            status.update(state="error", label="LLM 호출 실패")
            st.stop()

        st.write("3/3 JSON 파싱")
        try:
            data = json.loads(raw)
        except Exception:
            # LLM이 JSON 외에 다른 텍스트를 포함했을 경우 JSON만 추출 시도
            m = re.search(r"\{[\s\S]*\}", raw)
            if m:
                data = json.loads(m.group(0))
            else:
                st.error("JSON 파싱 실패. 원문 표시:")
                st.code(raw)
                status.update(state="error", label="파싱 실패")
                st.stop()

        status.update(state="complete", label="완료")

    st.session_state.last_result = data

# ================== 결과 렌더링 (디자인 강화) ==================
data = st.session_state.last_result
if data:
    t1, t2, t3 = st.tabs(["요약 (Feasibility)", "설계·코드 (Blueprint)", "PRD"])

    with t1:
        st.markdown("#### 💡 Apps Script 구현 적합도")
        score = float(data.get("feasibility", {}).get("score", 0.0))
        
        # 1. Progress Bar를 통해 점수 시각화
        st.progress(score)
        
        # 2. Metric과 Summary를 병렬 배치 (세련미 반영)
        colA, colB = st.columns([1, 3])
        with colA:
            # delta_color="off"로 불필요한 색상 변화 제거
            st.metric("최종 점수", f"{score * 100:.0f}점", delta_color="off")
        with colB:
            # st.info로 Summary 텍스트를 감싸 시각적 강조 및 여백 확보
            st.info(data.get("feasibility", {}).get("summary", ""))

        st.divider()
        
        st.markdown("#### 보완·범위 조정 제안")
        if data.get("adjustments"):
             for it in data.get("adjustments", []):
                st.markdown(f"• **{it}**")
        else:
            st.info("특이 사항 없음. 현재 아이디어 그대로 진행하셔도 좋습니다.")
        
        st.divider()
        
        st.markdown("#### 다음 단계")
        for idx, it in enumerate(data.get("next_steps", []), 1):
            st.write(f"{idx}. {it}")


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
            # 코드 블록 마크다운 제거
            code = sn.get("code","").replace("```js","").replace("```javascript","").replace("```","").strip()
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
if _is_admin_link():
    st.markdown("---")
    st.markdown("##### 관리자 포털")
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
        st.caption("연수 원고·레퍼런스 자산 업로드")
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
                st.rerun()
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
