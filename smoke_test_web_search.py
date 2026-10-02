#!/usr/bin/env python3
"""Minimal Mistral Web Search smoke test.

Runs one public-web query and prints the normalized text and source references.
It does not query OSV/CVEProject and does not send email.
"""

import os
from mistralai import Mistral

MODEL = os.environ.get("MISTRAL_SEARCH_MODEL", "mistral-small-latest")


def normalize(response) -> dict:
    text_parts = []
    sources = []
    seen_urls = set()

    for output in getattr(response, "outputs", []) or []:
        if getattr(output, "type", None) != "message.output":
            continue

        content = getattr(output, "content", "")
        if isinstance(content, str):
            text_parts.append(content)
            continue

        for chunk in content or []:
            chunk_type = getattr(chunk, "type", None)
            if chunk_type == "text":
                if getattr(chunk, "text", ""):
                    text_parts.append(chunk.text)
            elif chunk_type == "tool_reference":
                url = getattr(chunk, "url", "")
                if url and url not in seen_urls:
                    seen_urls.add(url)
                    sources.append({
                        "title": getattr(chunk, "title", "") or url,
                        "url": url,
                    })

    return {"text": "\n".join(text_parts).strip(), "sources": sources}


def main():
    api_key = os.environ.get("MISTRAL_API_KEY")
    if not api_key:
        raise SystemExit("Set MISTRAL_API_KEY before running this smoke test.")

    client = Mistral(api_key=api_key)
    response = client.beta.conversations.start(
        model=MODEL,
        inputs=[{
            "role": "user",
            "content": (
                "Search the public web for the latest official Mistral AI "
                "documentation about Web Search. Summarize it in two sentences "
                "and cite the sources you used."
            ),
        }],
        tools=[{"type": "web_search"}],
        store=False,
    )

    result = normalize(response)
    print("\n=== TEXT ===\n")
    print(result["text"] or "(no text returned)")
    print("\n=== SOURCES ===\n")
    if result["sources"]:
        for source in result["sources"]:
            print(f'- {source["title"]}: {source["url"]}')
    else:
        print("(no tool_reference sources returned)")


if __name__ == "__main__":
    main()
