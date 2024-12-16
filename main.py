from openai import OpenAI
import os
import openai


openai.api_key = os.getenv('OPENAI_API_KEY')


def summarize_code(file_path):
    with open(file_path, 'r') as file:
        code = file.read()
    client = OpenAI()
    response = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "system", "content": "You are a code documentation expert."},
            {"role": "user", "content": f"Summarize this Python code:\n{code}"}
        ]
    )
    return response.choices[0].message.content

def main():
    file_path = 'D:\\python_work\\youtube_bot\\classImplTranscription.py'
    summary = summarize_code(file_path)
    print(summary)

if __name__ == "__main__":
    main()
