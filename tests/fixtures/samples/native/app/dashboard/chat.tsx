// expected: 2 findings (a browser LLM client, and its public-prefixed key name)
"use client";
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function ask(question: string) {
  return client.chat.completions.create({
    model: "gpt-4",
    messages: [{ role: "user", content: question }],
  });
}
