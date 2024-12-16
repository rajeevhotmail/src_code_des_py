from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch

def setup_model():
    tokenizer = AutoTokenizer.from_pretrained("Salesforce/codet5-base")
    model = AutoModelForSeq2SeqLM.from_pretrained("Salesforce/codet5-base")
    return model, tokenizer

def summarize_code(file_path, model, tokenizer):
    with open(file_path, 'r') as file:
        code = file.read()

    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model.generate(**inputs, max_length=150, num_return_sequences=1)
    summary = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return summary

def main():
    file_path = 'D:\\python_work\\youtube_bot\\classImplTranscription.py'
    model, tokenizer = setup_model()
    summary = summarize_code(file_path, model, tokenizer)
    print("CodeT5 Summary:")
    print(summary)

if __name__ == "__main__":
    main()
