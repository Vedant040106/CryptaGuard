
import google.generativeai as genai
import os
from config import Config

api_key = Config.GEMINI_API_KEY
if not api_key:
    print("NO_API_KEY")
    exit(1)

genai.configure(api_key=api_key)

with open('models.txt', 'w') as f:
    try:
        for m in genai.list_models():
            f.write(f"{m.name}\n")
            print(m.name)
    except Exception as e:
        f.write(f"ERROR: {e}\n")
        print(e)
