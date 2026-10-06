# Evaluation summary

## ML layer: held-out test split

TF-IDF + Logistic Regression (C=16.0), trained on 22,257 de-duplicated examples, 20% stratified hold-out.

| Split | n | Precision | Recall | F1 | ROC-AUC | TN | FP | FN | TP |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| overall | 4,452 | 0.978 | 0.968 | 0.973 | 0.997 | 3008 | 31 | 45 | 1368 |
| sms | 1,027 | 0.936 | 0.952 | 0.944 | 0.993 | 895 | 8 | 6 | 118 |
| email | 3,425 | 0.982 | 0.970 | 0.976 | 0.998 | 2113 | 23 | 39 | 1250 |

A message counts as flagged when its score reaches the `suspicious` threshold (35) in rule and fused modes, or P(spam) >= 0.5 in the ML-only mode. The text classifier is English-only: fused modes skip it for Turkish messages, while the ML-only rows score every message as-is.

## Development scenarios (English) (20 scams, 11 legitimate)

_Hand-written while the rules were developed, so these numbers are optimistic._ Generated 2026-10-06T18:19:31+00:00.

| Mode | Precision | Recall | F1 | Accuracy | TN | FP | FN | TP | Scam-type accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rules | 1.000 | 1.000 | 1.000 | 1.000 | 11 | 0 | 0 | 20 | 0.800 |
| ml | 0.688 | 0.550 | 0.611 | 0.548 | 6 | 5 | 9 | 11 | n/a |
| fused-mock | 0.952 | 1.000 | 0.976 | 0.968 | 10 | 1 | 0 | 20 | 0.850 |
| fused-live | 0.952 | 1.000 | 0.976 | 0.968 | 10 | 1 | 0 | 20 | 0.950 |

### Per-scenario scores

| ID | Lang | Label | Expected type | rules | ml | fused-mock | fused-live |
|---|---|---|---|---:|---:|---:|---:|
| S01 | en | scam | family_impersonation | 85 | 2⚠ | 80 | 80 |
| S02 | en | scam | family_impersonation | 80 | 2⚠ | 80 | 80 |
| S03 | en | scam | ceo_invoice_fraud | 90 | 1⚠ | 80 | 80 |
| S04 | en | scam | ceo_invoice_fraud | 72 | 45⚠ | 64 | 64 |
| S05 | en | scam | ceo_invoice_fraud | 80 | 1⚠ | 80 | 80 |
| S06 | en | scam | fake_delivery | 80 | 34⚠ | 80 | 80 |
| S07 | en | scam | fake_delivery | 80 | 82 | 80 | 81 |
| S08 | en | scam | bank_impersonation | 53 | 97 | 66 | 69 |
| S09 | en | scam | bank_impersonation | 71 | 74 | 72 | 77 |
| S10 | en | scam | account_phishing | 60 | 85 | 67 | 70 |
| S11 | en | scam | account_phishing | 70 | 84 | 70 | 70 |
| S12 | en | scam | tech_support | 51 | 34⚠ | 46 | 51 |
| S13 | en | scam | government_impersonation | 36 | 75 | 48 | 61 |
| S14 | en | scam | government_impersonation | 80 | 68 | 80 | 80 |
| S15 | en | scam | investment_scam | 80 | 88 | 80 | 80 |
| S16 | en | scam | romance_scam | 80 | 8⚠ | 80 | 80 |
| S17 | en | scam | job_scam | 80 | 100 | 80 | 82 |
| S18 | en | scam | marketplace_scam | 80 | 17⚠ | 80 | 80 |
| S19 | en | scam | prize_lottery | 81 | 99 | 86 | 86 |
| S20 | en | scam | other | 88 | 75 | 84 | 88 |
| L01 | en | legit | none | 0 | 87⚠ | 27 | 17 |
| L02 | en | legit | none | 0 | 80⚠ | 25 | 23 |
| L03 | en | legit | none | 0 | 7 | 2 | 5 |
| L04 | en | legit | none | 0 | 0 | 0 | 0 |
| L05 | en | legit | none | 0 | 6 | 2 | 5 |
| L06 | en | legit | none | 0 | 2 | 1 | 0 |
| L07 | en | legit | none | 0 | 51⚠ | 16 | 14 |
| L08 | en | legit | none | 18 | 99⚠ | 43⚠ | 35⚠ |
| L09 | en | legit | none | 25 | 50 | 32 | 28 |
| L10 | en | legit | none | 0 | 84⚠ | 26 | 24 |
| L11 | en | legit | none | 18 | 15 | 17 | 18 |

⚠ = misclassified at the flagging threshold.

## Turkish scenarios (development) (9 scams, 7 legitimate)

_Hand-written while the Turkish rule pack was developed, so these numbers are optimistic._ Generated 2026-10-06T18:24:14+00:00.

| Mode | Precision | Recall | F1 | Accuracy | TN | FP | FN | TP | Scam-type accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rules | 1.000 | 1.000 | 1.000 | 1.000 | 7 | 0 | 0 | 9 | 1.000 |
| ml | 1.000 | 0.111 | 0.200 | 0.500 | 7 | 0 | 8 | 1 | n/a |
| fused-mock | 1.000 | 1.000 | 1.000 | 1.000 | 7 | 0 | 0 | 9 | 1.000 |
| fused-live | 1.000 | 1.000 | 1.000 | 1.000 | 7 | 0 | 0 | 9 | 1.000 |

### Per-scenario scores

| ID | Lang | Label | Expected type | rules | ml | fused-mock | fused-live |
|---|---|---|---|---:|---:|---:|---:|
| T01 | tr | scam | family_impersonation | 85 | 38⚠ | 85 | 87 |
| T02 | tr | scam | government_impersonation | 88 | 59 | 88 | 91 |
| T03 | tr | scam | fake_delivery | 80 | 28⚠ | 80 | 80 |
| T04 | tr | scam | bank_impersonation | 74 | 48⚠ | 74 | 81 |
| T05 | tr | scam | government_impersonation | 53 | 27⚠ | 53 | 67 |
| T06 | tr | scam | investment_scam | 80 | 50⚠ | 80 | 84 |
| T07 | tr | scam | marketplace_scam | 57 | 8⚠ | 57 | 58 |
| T08 | tr | scam | job_scam | 80 | 23⚠ | 80 | 80 |
| T09 | tr | scam | other | 89 | 25⚠ | 89 | 91 |
| LT1 | tr | legit | none | 0 | 40 | 0 | 4 |
| LT2 | tr | legit | none | 0 | 2 | 0 | 0 |
| LT3 | tr | legit | none | 0 | 9 | 0 | 0 |
| LT4 | tr | legit | none | 8 | 31 | 8 | 13 |
| LT5 | tr | legit | none | 0 | 8 | 0 | 0 |
| LT6 | tr | legit | none | 18 | 38 | 18 | 19 |
| LT7 | tr | legit | none | 0 | 23 | 0 | 9 |

⚠ = misclassified at the flagging threshold.
