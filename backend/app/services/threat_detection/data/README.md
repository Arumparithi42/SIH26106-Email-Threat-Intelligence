# Training dataset (synthetic, demo only)

`training_emails.csv` contains **105 short, hand-written, synthetic email texts** (25 legitimate, 20 per other class)
used to train the lightweight TF-IDF + Logistic Regression classifier.

| Label | Meaning |
| --- | --- |
| `legitimate` | Ordinary business / personal mail |
| `phishing` | Credential or payment-detail harvesting lures |
| `bec` | Business Email Compromise: payment/gift-card/bank-change fraud, secrecy, authority |
| `spoofing` | Impersonation language: claims to speak "on behalf of" an authority/organisation |
| `suspicious` | Spam/scam content that is not clearly one of the above |

Important:

- The texts were written for this prototype. They contain **no real people, emails or credentials**.
- The sample `.eml` files in `/samples` are **not** part of this dataset.
- Metrics reported by `/api/model` are computed at training time with **5-fold stratified
  cross-validation on this dataset only**. With ~100 synthetic examples they show the pipeline works;
  they do **not** estimate real-world accuracy. A real deployment must retrain on a large labelled
  corpus (e.g. public phishing corpora + organisation mail) and re-evaluate.
