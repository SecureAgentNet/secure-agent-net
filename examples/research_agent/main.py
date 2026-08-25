from dotenv import load_dotenv
from pydantic import BaseModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser 
from langchain_classic.agents import create_tool_calling_agent, AgentExecutor
from tools import search_tool, wiki_tool,save_tool

load_dotenv()

class ResearchResponse(BaseModel):
    topic:str
    research_summary: str
    key_findings: str
    sources:list[str]
    tools_used: list[str]
    recommendations:list[str]

llm= ChatOpenAI(model_name="gpt-4o", temperature=0.7)
parser= PydanticOutputParser(pydantic_object=ResearchResponse)

prompt = ChatPromptTemplate.from_messages(
    [
        (                                                                                        
        "system",
                """
                You are a research assistant that will help generate a research paper.
                Answer the user query and use the necessary tools.
                Wrap the output in this format and provide no other text\n{format_instructions}
                """,
                
        ),
        ("placeholder", "{chat_history}"),
        ("human", "{query}"),
        ("placeholder", "{agent_scratchpad}"),
    ]  
).partial(format_instructions=parser.get_format_instructions())

tools = [search_tool,wiki_tool,save_tool]
agent = create_tool_calling_agent(
    llm=llm,
    prompt=prompt,
    tools=tools,
)

agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)
query = input("What can i help you research?")
raw_response = agent_executor.invoke({"query": query})

output = raw_response.get("output")
if isinstance(output, list):
    output_text = output[0]["text"]
else:
    output_text = output

structured_response = parser.parse(output_text)
print(structured_response)

from tools import save_to_txt

def format_list(items):
    return "\n".join(f"  - {item}" for item in items) if items else "  (none)"

formatted_output = f"""
{'=' * 60}
RESEARCH OUTPUT
{'=' * 60}

TOPIC:
{structured_response.topic}

{'-' * 60}
RESEARCH SUMMARY:
{'-' * 60}
{structured_response.research_summary}

{'-' * 60}
KEY FINDINGS:
{'-' * 60}
{structured_response.key_findings}

{'-' * 60}
SOURCES:
{'-' * 60}
{format_list(structured_response.sources)}

{'-' * 60}
TOOLS USED:
{'-' * 60}
{format_list(structured_response.tools_used)}

{'-' * 60}
RECOMMENDATIONS:
{'-' * 60}
{format_list(structured_response.recommendations)}

{'=' * 60}
"""

save_to_txt(formatted_output)
