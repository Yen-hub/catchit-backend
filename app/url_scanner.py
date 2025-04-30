from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

class URLScanner:
    def __init__(self):
        self.model_name = "r3ddkahili/final-complete-malicious-url-model"
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
        self.label_map = {
            0: "Benign",
            1: "Defacement",
            2: "Phishing",
            3: "Malware"
        }

    def scan_url(self, url):
        inputs = self.tokenizer(url, return_tensors="pt", truncation=True, padding=True, max_length=128)
        with torch.no_grad():
            outputs = self.model(**inputs)
            prediction = torch.argmax(outputs.logits).item()
        
        result = {
            "url": url,
            "classification": self.label_map[prediction],
            "is_malicious": prediction != 0,
            "confidence": float(torch.softmax(outputs.logits, dim=1)[0][prediction])
        }
        return result