# Evaluation summary

_Generated 2026-10-06T13:26:34+00:00_

## ML layer: held-out test split

TF-IDF + Logistic Regression (C=16.0), trained on 22,257 de-duplicated examples, 20% stratified hold-out.

| Split | n | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| overall | 4,452 | 0.978 | 0.968 | 0.973 | 0.997 | 3008 | 31 | 45 | 1368 |
| sms | 1,027 | 0.936 | 0.952 | 0.944 | 0.993 | 895 | 8 | 6 | 118 |
| email | 3,425 | 0.982 | 0.970 | 0.976 | 0.998 | 2113 | 23 | 39 | 1250 |

## Hand-written modern scenarios (20 scams, 11 legitimate)

A message counts as flagged when its score reaches the `suspicious` threshold (35) for rule/fused modes, or P(spam) >= 0.5 for the ML-only mode.

| Mode | Precision | Recall | F1 | Accuracy | TN | FP | FN | TP | Scam-type accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rules | 1.000 | 1.000 | 1.000 | 1.000 | 11 | 0 | 0 | 20 | 0.800 |
| ml | 0.688 | 0.550 | 0.611 | 0.548 | 6 | 5 | 9 | 11 | n/a |

### Per-scenario scores

| ID | Label | Expected type | rules | ml |
|---|---|---|---:|---:|
| S01 | scam | family_impersonation | 85 | 2⚠ |
| S02 | scam | family_impersonation | 80 | 2⚠ |
| S03 | scam | ceo_invoice_fraud | 90 | 1⚠ |
| S04 | scam | ceo_invoice_fraud | 86 | 45⚠ |
| S05 | scam | ceo_invoice_fraud | 80 | 1⚠ |
| S06 | scam | fake_delivery | 80 | 34⚠ |
| S07 | scam | fake_delivery | 80 | 82 |
| S08 | scam | bank_impersonation | 53 | 97 |
| S09 | scam | bank_impersonation | 71 | 74 |
| S10 | scam | account_phishing | 60 | 85 |
| S11 | scam | account_phishing | 70 | 84 |
| S12 | scam | tech_support | 51 | 34⚠ |
| S13 | scam | government_impersonation | 36 | 75 |
| S14 | scam | government_impersonation | 80 | 68 |
| S15 | scam | investment_scam | 80 | 88 |
| S16 | scam | romance_scam | 80 | 8⚠ |
| S17 | scam | job_scam | 80 | 100 |
| S18 | scam | marketplace_scam | 80 | 17⚠ |
| S19 | scam | prize_lottery | 81 | 99 |
| S20 | scam | other | 88 | 75 |
| L01 | legit | none | 0 | 87⚠ |
| L02 | legit | none | 0 | 80⚠ |
| L03 | legit | none | 0 | 7 |
| L04 | legit | none | 0 | 0 |
| L05 | legit | none | 0 | 6 |
| L06 | legit | none | 0 | 2 |
| L07 | legit | none | 0 | 51⚠ |
| L08 | legit | none | 18 | 99⚠ |
| L09 | legit | none | 25 | 50 |
| L10 | legit | none | 0 | 84⚠ |
| L11 | legit | none | 18 | 15 |

⚠ = misclassified at the flagging threshold.
