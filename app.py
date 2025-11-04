# app.py

import streamlit as st
import os
import pandas as pd
import time
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_community.document_loaders import PyPDFLoader, CSVLoader
from langchain_community.vectorstores import FAISS
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains import ConversationalRetrievalChain
from langchain_experimental.agents.agent_toolkits import create_pandas_dataframe_agent
from langchain.memory import ConversationBufferMemory

# --- 1. 환경 설정 및 API 키 로드 ---

st.set_page_config(page_title="바이브코딩 AI 튜터 봇", page_icon="🤖")
st.title("🤖 바이브코딩 AI 튜터 봇")
st.markdown("Apps Script와 Gemini를 활용한 아이디어를 점검해 드립니다.")
st.markdown("---")

# Streamlit secrets에서 API 키 가져오기
try:
    OPENAI_API_KEY = st.secrets["OPENAI_API_KEY"]
    os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
except KeyError:
    st.error("OpenAI API 키가 설정되지 않았습니다. Streamlit secrets에 추가해주세요.")
    st.stop()

# --- 2. 데이터 로드 및 전처리 (RAG) ---
# 데이터 로드, 전처리, 벡터화는 리소스를 많이 사용하므로 캐시 처리합니다.

# 데이터 파일 경로 설정
PDF_FILE_PATH = os.path.join("data", "course_handout.pdf")
CSV_FILE_PATH = os.path.join("data", "instructor_feedback.csv")

@st.cache_resource(show_spinner="🗂️ 챗봇 두뇌(지식) 로딩 중...")
def load_and_build_knowledge_base():
    """
    data 폴더에서 PDF와 CSV 파일을 로드하고 FAISS 벡터 스토어를 생성합니다.
    """
    documents = []
    
    # PDF 로드
    try:
        pdf_loader = PyPDFLoader(PDF_FILE_PATH)
        documents.extend(pdf_loader.load())
    except Exception as e:
        st.warning(f"PDF 파일 로드 실패: {e}. 'data/course_handout.pdf' 파일을 확인하세요.")

    # 텍스트 분할
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
    split_docs = text_splitter.split_documents(documents)
    
    # 임베딩 및 벡터 스토어 생성
    embeddings = OpenAIEmbeddings()
    try:
        vector_store = FAISS.from_documents(split_docs, embeddings)
    except Exception as e:
        st.error(f"벡터 스토어 생성 실패: {e}. PDF 문서를 찾을 수 없거나 비어있을 수 있습니다.")
        return None, None

    # CSV 로드 (Pandas Agent 용)
    try:
        df = pd.read_csv(CSV_FILE_PATH)
    except Exception as e:
        st.warning(f"CSV 파일 로드 실패: {e}. 'data/instructor_feedback.csv' 파일을 확인하세요.")
        return vector_store, None

    return vector_store, df

# --- 3. LangChain 에이전트 및 체인 생성 ---

# 1) RAG (PDF) 및 2) Pandas (CSV) 로드
vector_store, df = load_and_build_knowledge_base()

# LLM 모델 정의
llm = ChatOpenAI(model_name="gpt-4o", temperature=0)

# 3) 대화 메모리 초기화
# session_state에 메모리 저장
if "chat_memory" not in st.session_state:
    st.session_state.chat_memory = ConversationBufferMemory(
        memory_key="chat_history", 
        return_messages=True
    )
memory = st.session_state.chat_memory

# 4) RAG 체인 생성 (PDF 문서 검색용)
# ConversationalRetrievalChain: RAG + 메모리
pdf_chain = None
if vector_store:
    pdf_chain = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=vector_store.as_retriever(),
        memory=memory,
        chain_type="stuff",
        # 시스템 프롬프트 (조정 가능)
        combine_docs_chain_kwargs={
            "prompt": st.chat_input(
                "당신은 바이브코딩 연수 튜터입니다. 교사의 질문에 대해 **반드시 '참고 자료'에 근거해서** 전문적이고 친절하게 답변하세요.\n"
                "자료에 없는 내용은 '학습 자료에 없는 내용입니다'라고 답하세요.\n\n"
                "참고 자료:\n{context}\n\n"
                "질문: {question}"
            )
        }
    )

# 5) Pandas DataFrame 에이전트 생성 (CSV 피드백 검색용)
pandas_agent = None
if df is not None:
    pandas_agent = create_pandas_dataframe_agent(
        llm,
        df,
        verbose=True, # 에이전트 작동 과정을 볼 수 있음 (디버깅용)
        allow_dangerous_code=True, # CSV 분석을 위해 Python 코드 실행 허용
        agent_type="openai-functions",
        # 에이전트 프롬프트 (가장 중요)
        prompt=(
            "당신은 '바이브코딩 강사 피드백' CSV 데이터를 분석하는 AI입니다. "
            "이 데이터는 교사들의 아이디어와 그에 대한 강사의 피드백을 담고 있습니다. "
            "사용자의 질문이 이 데이터와 관련 있는지 판단하세요. "
            "CSV의 'idea_summary' 컬럼을 중심으로 질문과 가장 유사한 행을 찾으세요. "
            "찾았다면, 해당 행의 'feasibility_apps_script'(구현가능성), 'instructor_feedback'(강사피드백), 'alternative_suggestion'(대안)을 **그대로** 인용하여 답변하세요."
        )
    )

# --- 4. Streamlit 챗봇 UI 로직 ---

# 1) 세션 상태에 메시지 히스토리 초기화
if "messages" not in st.session_state:
    st.session_state.messages = [{"role": "assistant", "content": "안녕하세요! 어떤 아이디어를 구상 중이신가요?"}]

# 2) 이전 대화 내용 표시
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# 3) 사용자 입력 받기
if prompt := st.chat_input("아이디어에 대해 질문해주세요..."):
    # 4) 사용자 메시지 표시
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    # 5) 챗봇 답변 생성
    with st.chat_message("assistant"):
        response_content = ""
        # 5-1: 먼저 Pandas 에이전트(CSV)에게 질문
        try:
            if pandas_agent:
                with st.spinner("🔄 강사 피드백을 확인하는 중..."):
                    # "agent_scratchpad"는 에이전트의 생각을 저장하는 임시 공간입니다.
                    # chat_history를 포함하여 질문을 전달합니다.
                    agent_response = pandas_agent.invoke({
                        "input": f"사용자 질문: {prompt}\n\n대화 기록:\n{st.session_state.chat_memory.chat_history.messages}",
                    })
                    response_content = agent_response["output"]
            
            # 5-2: CSV에서 유의미한 답을 못 찾았을 경우, RAG 체인(PDF)에게 질문
            # (간단한 로직: Pandas가 너무 짧은 답변을 했거나, '모르겠다'고 했을 때)
            if not response_content or len(response_content) < 50 or "모르겠다" in response_content:
                if pdf_chain:
                    with st.spinner("📚 연수 자료를 검색하는 중..."):
                        # RAG 체인은 메모리를 자동으로 참조합니다.
                        pdf_response = pdf_chain.invoke({"question": prompt})
                        response_content = pdf_response["answer"]
                else:
                    response_content = "죄송합니다, 현재 PDF 연수 자료를 참조할 수 없습니다."
            
        except Exception as e:
            st.error(f"답변 생성 중 오류가 발생했습니다: {e}")
            response_content = "죄송합니다, 답변을 처리하는 데 문제가 발생했습니다. 관리자에게 문의하세요."

        # 5-3: 스트리밍 효과로 답변 표시
        message_placeholder = st.empty()
        full_response = ""
        for chunk in response_content.split():
            full_response += chunk + " "
            time.sleep(0.05)  # 딜레이
            message_placeholder.markdown(full_response + "▌")
        message_placeholder.markdown(full_response)
    
    # 6) 챗봇 메시지 히스토리에 저장
    st.session_state.messages.append({"role": "assistant", "content": full_response})
