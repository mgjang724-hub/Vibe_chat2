import os, io, re, json, hashlib
from datetime import datetime
from typing import Dict, Any, List

import streamlit as st
from openai import OpenAI

# ================== 전역 설정 및 LLM 초기화 ==================
st.set_page_config(page_title="바이브코딩 GAS 튜터", page_icon="🧩", layout="wide")

# 반드시 먼저 정의
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or st.secrets.get("OPENAI_API_KEY", "")
MODEL = os.getenv("OPENAI_MODEL") or st.secrets.get("OPENAI_MODEL", "gpt-4o-mini")
ADMIN_PASSWORD = st.secrets.get("ADMIN_PASSWORD", "")

# OpenAI 안전 초기화
if OPENAI_API_KEY:
    os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
    client = OpenAI()  # 인자 없이 생성
else:
    client = None

# ================== 유틸 ==================
def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def is_admin() -> bool:
    return bool(st.session_state.get("is_admin", False))

def admin_gate_ui():
    with st.sidebar:
        st.subheader("관리자")
        if not is_admin():
            pwd = st.text_input("비밀번호", type="password")
            if st.button("로그인"):
                if ADMIN_PASSWORD and _sha256(pwd) == _sha256(ADMIN_PASSWORD):
                    st.session_state.is_admin = True
                    st.success("관리자 로그인")
                    st.rerun()
                else:
                    st.error("인증 실패")
        else:
            st.caption(f"로그인됨 · {datetime.now().strftime('%H:%M:%S')}")
            if st.button("로그아웃"):
                st.session_state.is_admin = False
                st.rerun()

def read_file_to_text(upload) -> str:
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

def rule_check(text: str) -> Dict[str, Any]:
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

def call_openai(system: str, user: str) -> str:
    if not client:
        return json.dumps({"error":"OPENAI_API_KEY 필요"})
    resp = client.chat.completions.create(
        model=MODEL,
        temperature=0.15,
        messages=[{"role":"system","content":system},
                  {"role":"user","content":user}]
    )
    return resp.choices[0].message.content.strip()

# ================== UI 헤더 ==================
st.title("바이브코딩 Apps Script 튜터")
st.caption("입력: 제목·설명, 주 사용자, 구현 기능 → 출력: Apps Script 가능성 판단, 보완 제안, 블루프린트, 예시 코드, PRD")

admin_gate_ui()

# ================== 사이드바(관리자만 학습 업데이트) ==================
with st.sidebar:
    st.header("지식(연수 원고·레퍼런스)")
    if "corpus_text" not in st.session_state:
        st.session_state.corpus_text = ""
    if is_admin():
        uploads = st.file_uploader("PDF/TXT/MD 업로드", type=["pdf","txt","md"], accept_multiple_files=True)
        if uploads:
            texts = []
            for up in uploads:
                texts.append(read_file_to_text(up))
            st.session_state.corpus_text = "\n\n".join(texts)
            st.success(f"문서 {len(uploads)}개 로드 완료")
        if st.button("현재 지식 삭제"):
            st.session_state.corpus_text = ""
            st.warning("지식 초기화 완료")
    else:
        st.caption("관리자만 지식을 업데이트할 수 있습니다.")

    st.divider()
    st.subheader("상태")
    st.write(f"LLM 모델: `{MODEL}`")
    st.write("지식 길이:", len(st.session_state.corpus_text))

# ================== 사용자 입력 폼 ==================
with st.form("idea_form"):
    col1, col2 = st.columns([2,1])
    with col1:
        title = st.text_input("1) 제목", placeholder="예) 학급 공지·과제 리마인더 자동화")
    with col2:
        users = st.text_input("2) 주 사용자", placeholder="예) 담임교사, 학생, 행정실")

    desc = st.text_area("설명", placeholder="아이디어의 배경과 목적을 작성", height=120)
    features = st.text_area("3) 구현하려는 기능", placeholder="- 주간 리마인더 메일 발송\n- Google Form 응답 자동 집계\n- 승인/반려 워크플로", height=160)
    submitted = st.form_submit_button("가능성 평가 + 보완 제안 + PRD 생성", type="primary")

# ================== 생성 로직 ==================
if submitted:
    idea_block = f"제목: {title}\n설명: {desc}\n주 사용자: {users}\n기능:\n{features}"
    rc = rule_check(idea_block)

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
- Apps Script WebApp(doGet/doPost) for webhook/폼 수신
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

[지식(관리자 업로드)]
{st.session_state.corpus_text[:8000] if st.session_state.corpus_text else "(지식 없음)"}

JSON만 출력하라.
"""

    with st.spinner("생성 중"):
        raw = call_openai(SYSTEM, user_prompt)

    # JSON 파싱
    try:
        data = json.loads(raw)
    except Exception:
        m = re.search(r"\{[\s\S]*\}", raw)
        data = json.loads(m.group(0)) if m else {"error":"JSON 파싱 실패", "raw":raw}

    # 결과 표시
    colA, colB = st.columns([1,2])
    with colA:
        score = float(data.get("feasibility", {}).get("score", rc["score"]))
        st.metric("Apps Script 가능성", f"{score:.2f}")
        st.write(data.get("feasibility", {}).get("summary",""))
        st.markdown("**리스크**")
        st.write(data.get("risks", []))

    with colB:
        st.markdown("### 보완·범위 조정 제안")
        for it in data.get("adjustments", []):
            st.write("• " + it)

        st.markdown("### 설계 블루프린트(JSON)")
        blueprint = data.get("blueprint", {})
        st.json(blueprint)
        st.download_button(
            "블루프린트 JSON 다운로드",
            json.dumps(blueprint, ensure_ascii=False, indent=2).encode("utf-8"),
            file_name="blueprint.json"
        )

        st.markdown("### 예시 Apps Script 스니펫")
        for sn in data.get("gas_snippets", []):
            code = sn.get("code","").replace("```js","").replace("```javascript","").replace("```","")
            st.markdown(f"**{sn.get('title','스니펫')}**")
            st.code(code, language="javascript")

        prd_md = data.get("prd","")
        if prd_md:
            st.markdown("### PRD 초안")
            st.markdown(prd_md)
            st.download_button("PRD.md 다운로드", prd_md.encode("utf-8"), file_name="PRD.md")

        st.markdown("### 다음 단계")
        for it in data.get("next_steps", []):
            st.write(it)

    with st.expander("규칙 기반 1차 판정 세부"):
        st.json(rc)

st.divider()
st.caption("관리자만 지식을 업데이트. 일반 사용자는 조회·질의만.")
