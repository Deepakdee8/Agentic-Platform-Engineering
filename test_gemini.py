
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

llm = ChatGoogleGenerativeAI(
    model="gemini-3.5-flash-lite",
    temperature=0,
)

response = llm.invoke([
                    SystemMessage(content="You are an helpfull assistant"),
                    HumanMessage(content="Explain what LangGraph does in two sentences.")]),
                
    

print(response.content)
