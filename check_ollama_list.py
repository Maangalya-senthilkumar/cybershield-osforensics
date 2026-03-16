import ollama
import json

try:
    client = ollama.Client(host="http://localhost:11434")
    res = client.list()
    print(f"Type: {type(res)}")
    # If it's a ListModelsResponse (as in newer ollama versions)
    # it may have a .models attribute
    if hasattr(res, 'models'):
        print("Has .models attribute")
        for m in res.models:
             print(f"Model: {m}")
             print(f"Model type: {type(m)}")
    else:
        print(f"Res: {res}")
except Exception as e:
    print(f"Error: {e}")
