from langchain_community.tools import DuckDuckGoSearchRun
from langchain_classic.tools import Tool
from datetime import datetime
import wikipediaapi

def save_to_txt(data: str ,filename: str ="research_output.txt"):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    formatted_text = f"--- Research Output ---\nTimestamp: {timestamp}\n\n{data}\n\n"

    with open(filename, "a", encoding="utf-8") as f:
        f.write(formatted_text)

    return f"Data saved to {filename} at {timestamp}"

save_tool = Tool(
    name="save_text_to_file",
        func=save_to_txt,
        description="Saves structured research data to a text file.",
    )

search = DuckDuckGoSearchRun()
search_tool = Tool(
    name="search",
    func=search.run,
    description="Search the web for information",
)

wiki_wiki = wikipediaapi.Wikipedia(
    user_agent='ResearchAgent/1.0 (contact: youremail@example.com)',
    language='en'
)

def wikipedia_search(query: str) -> str:
    page = wiki_wiki.page(query)
    if not page.exists():
        return f"No Wikipedia page found for '{query}'."
    return page.summary[:1000]

wiki_tool = Tool(
    name="wikipedia",
    func=wikipedia_search,
    description="Useful for looking up factual information on Wikipedia. Input should be a search term.",
)
