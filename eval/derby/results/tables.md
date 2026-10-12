# Derby evaluation: generated tables

### real (n = 1069; labels {'safe': 888, 'suspicious': 133, 'dangerous': 48})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.53 (0.40–0.66) | 0.15 (0.10–0.21) | 0.23 | 0.03 | 27 | 24 | 154 | 864 | 0.38 | 0.82 | 1069/1069 |
| Text classifier | 0.39 (0.34–0.43) | 0.88 (0.83–0.92) | 0.54 | 0.28 | 160 | 253 | 21 | 635 | 0.41 | 0.65 | 1069/1069 |
| AI analyst, alone | 0.52 (0.47–0.58) | 0.97 (0.94–0.99) | 0.68 | 0.18 | 174 | 159 | 5 | 715 | 0.45 | 0.74 | 1053/1069 |
| AI analyst, in the system | 0.59 (0.53–0.65) | 0.96 (0.92–0.98) | 0.73 | 0.14 | 172 | 119 | 8 | 755 | 0.47 | 0.77 | 1054/1069 |
| Rules + classifier (instant) | 0.77 (0.69–0.84) | 0.56 (0.49–0.63) | 0.65 | 0.03 | 102 | 30 | 79 | 858 | 0.54 | 0.87 | 1069/1069 |
| Full system | 0.62 (0.57–0.68) | 0.94 (0.89–0.97) | 0.75 | 0.12 | 170 | 102 | 11 | 786 | 0.59 | 0.85 | 1069/1069 |

### real_tr_sms (n = 669; labels {'safe': 654, 'suspicious': 11, 'dangerous': 4})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.20 (0.08–0.42) | 0.27 (0.11–0.52) | 0.23 | 0.02 | 4 | 16 | 11 | 638 | 0.33 | 0.95 | 669/669 |
| Text classifier | 0.03 (0.01–0.06) | 0.40 (0.20–0.64) | 0.05 | 0.33 | 6 | 215 | 9 | 439 | 0.28 | 0.66 | 669/669 |
| AI analyst, alone | 0.08 (0.05–0.14) | 0.80 (0.55–0.93) | 0.15 | 0.20 | 12 | 131 | 3 | 509 | 0.33 | 0.78 | 655/669 |
| AI analyst, in the system | 0.11 (0.06–0.19) | 0.73 (0.48–0.89) | 0.19 | 0.14 | 11 | 88 | 4 | 554 | 0.34 | 0.85 | 657/669 |
| Rules + classifier (instant) | 0.20 (0.08–0.42) | 0.27 (0.11–0.52) | 0.23 | 0.02 | 4 | 16 | 11 | 638 | 0.33 | 0.95 | 669/669 |
| Full system | 0.13 (0.08–0.22) | 0.73 (0.48–0.89) | 0.23 | 0.11 | 11 | 71 | 4 | 583 | 0.36 | 0.88 | 669/669 |

### real_en_email (n = 400; labels {'dangerous': 44, 'safe': 234, 'suspicious': 122})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.74 (0.57–0.86) | 0.14 (0.09–0.20) | 0.23 | 0.03 | 23 | 8 | 143 | 226 | 0.34 | 0.60 | 400/400 |
| Text classifier | 0.80 (0.74–0.85) | 0.93 (0.88–0.96) | 0.86 | 0.16 | 154 | 38 | 12 | 196 | 0.48 | 0.62 | 400/400 |
| AI analyst, alone | 0.85 (0.80–0.90) | 0.99 (0.96–1.00) | 0.92 | 0.12 | 162 | 28 | 2 | 206 | 0.52 | 0.67 | 398/400 |
| AI analyst, in the system | 0.84 (0.78–0.88) | 0.98 (0.94–0.99) | 0.90 | 0.13 | 161 | 31 | 4 | 201 | 0.50 | 0.65 | 397/400 |
| Rules + classifier (instant) | 0.88 (0.80–0.92) | 0.59 (0.51–0.66) | 0.70 | 0.06 | 98 | 14 | 68 | 220 | 0.53 | 0.73 | 400/400 |
| Full system | 0.84 (0.78–0.88) | 0.96 (0.92–0.98) | 0.89 | 0.13 | 159 | 31 | 7 | 203 | 0.64 | 0.81 | 400/400 |

### synthetic (n = 150; labels {'suspicious': 50, 'dangerous': 50, 'safe': 50})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.93 (0.83–0.97) | 0.53 (0.43–0.62) | 0.68 | 0.08 | 53 | 4 | 47 | 46 | 0.45 | 0.49 | 150/150 |
| Text classifier | 0.74 (0.64–0.82) | 0.67 (0.57–0.75) | 0.70 | 0.48 | 67 | 24 | 33 | 26 | 0.41 | 0.41 | 150/150 |
| AI analyst, alone | 0.94 (0.86–0.98) | 0.65 (0.55–0.74) | 0.77 | 0.08 | 65 | 4 | 35 | 45 | 0.59 | 0.64 | 149/150 |
| AI analyst, in the system | 0.94 (0.87–0.97) | 0.80 (0.71–0.86) | 0.86 | 0.10 | 79 | 5 | 20 | 45 | 0.71 | 0.72 | 149/150 |
| Rules + classifier (instant) | 0.93 (0.84–0.97) | 0.55 (0.45–0.64) | 0.69 | 0.08 | 55 | 4 | 45 | 46 | 0.47 | 0.50 | 150/150 |
| Full system | 0.92 (0.84–0.96) | 0.69 (0.59–0.77) | 0.79 | 0.12 | 69 | 6 | 31 | 44 | 0.53 | 0.55 | 150/150 |

### synthetic_en (n = 75; labels {'suspicious': 25, 'dangerous': 25, 'safe': 25})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.90 (0.74–0.96) | 0.52 (0.39–0.65) | 0.66 | 0.12 | 26 | 3 | 24 | 22 | 0.39 | 0.44 | 75/75 |
| Text classifier | 0.68 (0.53–0.81) | 0.52 (0.39–0.65) | 0.59 | 0.48 | 26 | 12 | 24 | 13 | 0.36 | 0.39 | 75/75 |
| AI analyst, alone | 1.00 (0.88–1.00) | 0.54 (0.40–0.67) | 0.70 | 0.00 | 27 | 0 | 23 | 24 | 0.59 | 0.64 | 74/75 |
| AI analyst, in the system | 0.95 (0.84–0.99) | 0.78 (0.65–0.87) | 0.86 | 0.08 | 39 | 2 | 11 | 23 | 0.71 | 0.72 | 75/75 |
| Rules + classifier (instant) | 0.90 (0.75–0.97) | 0.56 (0.42–0.69) | 0.69 | 0.12 | 28 | 3 | 22 | 22 | 0.43 | 0.47 | 75/75 |
| Full system | 0.92 (0.79–0.97) | 0.68 (0.54–0.79) | 0.78 | 0.12 | 34 | 3 | 16 | 22 | 0.48 | 0.51 | 75/75 |

### synthetic_tr (n = 75; labels {'safe': 25, 'dangerous': 25, 'suspicious': 25})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.96 (0.82–0.99) | 0.54 (0.40–0.67) | 0.69 | 0.04 | 27 | 1 | 23 | 24 | 0.51 | 0.53 | 75/75 |
| Text classifier | 0.77 (0.65–0.86) | 0.82 (0.69–0.90) | 0.80 | 0.48 | 41 | 12 | 9 | 13 | 0.45 | 0.44 | 75/75 |
| AI analyst, alone | 0.91 (0.78–0.96) | 0.76 (0.63–0.86) | 0.83 | 0.16 | 38 | 4 | 12 | 21 | 0.60 | 0.65 | 75/75 |
| AI analyst, in the system | 0.93 (0.81–0.98) | 0.82 (0.69–0.90) | 0.87 | 0.12 | 40 | 3 | 9 | 22 | 0.71 | 0.73 | 74/75 |
| Rules + classifier (instant) | 0.96 (0.82–0.99) | 0.54 (0.40–0.67) | 0.69 | 0.04 | 27 | 1 | 23 | 24 | 0.51 | 0.53 | 75/75 |
| Full system | 0.92 (0.79–0.97) | 0.70 (0.56–0.81) | 0.80 | 0.12 | 35 | 3 | 15 | 22 | 0.58 | 0.59 | 75/75 |

### synthetic_sms (n = 50; labels {'safe': 17, 'suspicious': 17, 'dangerous': 16})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 1.00 (0.77–1.00) | 0.39 (0.25–0.56) | 0.56 | 0.00 | 13 | 0 | 20 | 17 | 0.31 | 0.40 | 50/50 |
| Text classifier | 0.75 (0.57–0.87) | 0.64 (0.47–0.78) | 0.69 | 0.41 | 21 | 7 | 12 | 10 | 0.37 | 0.38 | 50/50 |
| AI analyst, alone | 0.95 (0.78–0.99) | 0.64 (0.47–0.78) | 0.76 | 0.06 | 21 | 1 | 12 | 16 | 0.65 | 0.68 | 50/50 |
| AI analyst, in the system | 0.96 (0.81–0.99) | 0.78 (0.61–0.89) | 0.86 | 0.06 | 25 | 1 | 7 | 16 | 0.77 | 0.78 | 49/50 |
| Rules + classifier (instant) | 1.00 (0.77–1.00) | 0.39 (0.25–0.56) | 0.56 | 0.00 | 13 | 0 | 20 | 17 | 0.31 | 0.40 | 50/50 |
| Full system | 0.95 (0.76–0.99) | 0.58 (0.41–0.73) | 0.72 | 0.06 | 19 | 1 | 14 | 16 | 0.42 | 0.46 | 50/50 |

### synthetic_whatsapp (n = 50; labels {'suspicious': 17, 'dangerous': 17, 'safe': 16})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.95 (0.76–0.99) | 0.56 (0.40–0.71) | 0.70 | 0.06 | 19 | 1 | 15 | 15 | 0.54 | 0.56 | 50/50 |
| Text classifier | 0.79 (0.62–0.90) | 0.68 (0.51–0.81) | 0.73 | 0.38 | 23 | 6 | 11 | 10 | 0.55 | 0.54 | 50/50 |
| AI analyst, alone | 0.96 (0.80–0.99) | 0.68 (0.51–0.81) | 0.79 | 0.06 | 23 | 1 | 11 | 15 | 0.62 | 0.68 | 50/50 |
| AI analyst, in the system | 0.93 (0.79–0.98) | 0.82 (0.67–0.92) | 0.88 | 0.12 | 28 | 2 | 6 | 14 | 0.72 | 0.72 | 50/50 |
| Rules + classifier (instant) | 0.95 (0.78–0.99) | 0.62 (0.45–0.76) | 0.75 | 0.06 | 21 | 1 | 13 | 15 | 0.56 | 0.58 | 50/50 |
| Full system | 0.93 (0.77–0.98) | 0.77 (0.60–0.88) | 0.84 | 0.12 | 26 | 2 | 8 | 14 | 0.59 | 0.60 | 50/50 |

### synthetic_email (n = 50; labels {'safe': 17, 'dangerous': 17, 'suspicious': 16})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.88 (0.69–0.96) | 0.64 (0.47–0.78) | 0.74 | 0.18 | 21 | 3 | 12 | 14 | 0.48 | 0.50 | 50/50 |
| Text classifier | 0.68 (0.51–0.81) | 0.70 (0.53–0.83) | 0.69 | 0.65 | 23 | 11 | 10 | 6 | 0.31 | 0.32 | 50/50 |
| AI analyst, alone | 0.91 (0.73–0.98) | 0.64 (0.47–0.78) | 0.75 | 0.12 | 21 | 2 | 12 | 14 | 0.50 | 0.57 | 49/50 |
| AI analyst, in the system | 0.93 (0.77–0.98) | 0.79 (0.62–0.89) | 0.85 | 0.12 | 26 | 2 | 7 | 15 | 0.65 | 0.68 | 50/50 |
| Rules + classifier (instant) | 0.88 (0.69–0.96) | 0.64 (0.47–0.78) | 0.74 | 0.18 | 21 | 3 | 12 | 14 | 0.51 | 0.52 | 50/50 |
| Full system | 0.89 (0.72–0.96) | 0.73 (0.56–0.85) | 0.80 | 0.18 | 24 | 3 | 9 | 14 | 0.58 | 0.58 | 50/50 |

### synthetic_payment (n = 81; labels {'suspicious': 28, 'dangerous': 37, 'safe': 16})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.93 (0.81–0.98) | 0.61 (0.49–0.72) | 0.74 | 0.19 | 40 | 3 | 25 | 13 | 0.42 | 0.42 | 81/81 |
| Text classifier | 0.86 (0.74–0.93) | 0.66 (0.54–0.77) | 0.75 | 0.44 | 43 | 7 | 22 | 9 | 0.40 | 0.42 | 81/81 |
| AI analyst, alone | 0.98 (0.89–1.00) | 0.74 (0.62–0.83) | 0.84 | 0.07 | 48 | 1 | 17 | 14 | 0.59 | 0.65 | 80/81 |
| AI analyst, in the system | 0.95 (0.86–0.98) | 0.89 (0.79–0.95) | 0.92 | 0.19 | 58 | 3 | 7 | 13 | 0.72 | 0.74 | 81/81 |
| Rules + classifier (instant) | 0.93 (0.82–0.98) | 0.63 (0.51–0.74) | 0.75 | 0.19 | 41 | 3 | 24 | 13 | 0.44 | 0.43 | 81/81 |
| Full system | 0.94 (0.85–0.98) | 0.77 (0.65–0.85) | 0.85 | 0.19 | 50 | 3 | 15 | 13 | 0.53 | 0.52 | 81/81 |

### synthetic_ai_agent (n = 17; labels {'safe': 6, 'dangerous': 6, 'suspicious': 5})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 1.00 (0.68–1.00) | 0.73 (0.43–0.90) | 0.84 | 0.00 | 8 | 0 | 3 | 6 | 0.61 | 0.65 | 17/17 |
| Text classifier | 0.77 (0.50–0.92) | 0.91 (0.62–0.98) | 0.83 | 0.50 | 10 | 3 | 1 | 3 | 0.48 | 0.47 | 17/17 |
| AI analyst, alone | 1.00 (0.68–1.00) | 0.73 (0.43–0.90) | 0.84 | 0.00 | 8 | 0 | 3 | 6 | 0.61 | 0.65 | 17/17 |
| AI analyst, in the system | 1.00 (0.72–1.00) | 0.91 (0.62–0.98) | 0.95 | 0.00 | 10 | 0 | 1 | 6 | 0.75 | 0.77 | 17/17 |
| Rules + classifier (instant) | 1.00 (0.68–1.00) | 0.73 (0.43–0.90) | 0.84 | 0.00 | 8 | 0 | 3 | 6 | 0.61 | 0.65 | 17/17 |
| Full system | 1.00 (0.72–1.00) | 0.91 (0.62–0.98) | 0.95 | 0.00 | 10 | 0 | 1 | 6 | 0.68 | 0.71 | 17/17 |

### synthetic_bank_change (n = 16; labels {'suspicious': 8, 'dangerous': 5, 'safe': 3})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.70 (0.40–0.89) | 0.54 (0.29–0.77) | 0.61 | 1.00 | 7 | 3 | 6 | 0 | 0.27 | 0.31 | 16/16 |
| Text classifier | 1.00 (0.70–1.00) | 0.69 (0.42–0.87) | 0.82 | 0.00 | 9 | 0 | 4 | 3 | 0.44 | 0.44 | 16/16 |
| AI analyst, alone | 0.90 (0.60–0.98) | 0.69 (0.42–0.87) | 0.78 | 0.50 | 9 | 1 | 4 | 1 | 0.41 | 0.47 | 15/16 |
| AI analyst, in the system | 0.79 (0.52–0.92) | 0.85 (0.58–0.96) | 0.81 | 1.00 | 11 | 3 | 2 | 0 | 0.30 | 0.38 | 16/16 |
| Rules + classifier (instant) | 0.73 (0.43–0.90) | 0.61 (0.35–0.82) | 0.67 | 1.00 | 8 | 3 | 5 | 0 | 0.26 | 0.31 | 16/16 |
| Full system | 0.77 (0.50–0.92) | 0.77 (0.50–0.92) | 0.77 | 1.00 | 10 | 3 | 3 | 0 | 0.28 | 0.38 | 16/16 |

### synthetic_links (n = 54; labels {'suspicious': 20, 'safe': 15, 'dangerous': 19})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.95 (0.76–0.99) | 0.49 (0.34–0.64) | 0.64 | 0.07 | 19 | 1 | 20 | 14 | 0.32 | 0.35 | 54/54 |
| Text classifier | 0.76 (0.60–0.87) | 0.72 (0.56–0.83) | 0.74 | 0.60 | 28 | 9 | 11 | 6 | 0.35 | 0.35 | 54/54 |
| AI analyst, alone | 0.96 (0.79–0.99) | 0.56 (0.41–0.71) | 0.71 | 0.07 | 22 | 1 | 17 | 14 | 0.57 | 0.59 | 54/54 |
| AI analyst, in the system | 1.00 (0.88–1.00) | 0.74 (0.58–0.85) | 0.85 | 0.00 | 28 | 0 | 10 | 15 | 0.71 | 0.72 | 53/54 |
| Rules + classifier (instant) | 0.95 (0.77–0.99) | 0.51 (0.36–0.66) | 0.67 | 0.07 | 20 | 1 | 19 | 14 | 0.34 | 0.37 | 54/54 |
| Full system | 0.96 (0.81–0.99) | 0.64 (0.48–0.77) | 0.77 | 0.07 | 25 | 1 | 14 | 14 | 0.45 | 0.46 | 54/54 |

### synthetic_tr_no_tr_letters (n = 21; labels {'safe': 7, 'dangerous': 7, 'suspicious': 7})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 1.00 (0.61–1.00) | 0.43 (0.21–0.67) | 0.60 | 0.00 | 6 | 0 | 8 | 7 | 0.48 | 0.52 | 21/21 |
| Text classifier | 0.69 (0.44–0.86) | 0.79 (0.52–0.92) | 0.73 | 0.71 | 11 | 5 | 3 | 2 | 0.34 | 0.33 | 21/21 |
| AI analyst, alone | 0.91 (0.62–0.98) | 0.71 (0.45–0.88) | 0.80 | 0.14 | 10 | 1 | 4 | 6 | 0.49 | 0.62 | 21/21 |
| AI analyst, in the system | 0.91 (0.62–0.98) | 0.77 (0.50–0.92) | 0.83 | 0.14 | 10 | 1 | 3 | 6 | 0.69 | 0.70 | 20/21 |
| Rules + classifier (instant) | 1.00 (0.61–1.00) | 0.43 (0.21–0.67) | 0.60 | 0.00 | 6 | 0 | 8 | 7 | 0.48 | 0.52 | 21/21 |
| Full system | 0.89 (0.56–0.98) | 0.57 (0.33–0.79) | 0.69 | 0.14 | 8 | 1 | 6 | 6 | 0.45 | 0.48 | 21/21 |

### synthetic_easy (n = 41; labels {'dangerous': 18, 'suspicious': 8, 'safe': 15})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 1.00 (0.81–1.00) | 0.61 (0.42–0.78) | 0.76 | 0.00 | 16 | 0 | 10 | 15 | 0.42 | 0.51 | 41/41 |
| Text classifier | 0.76 (0.58–0.88) | 0.85 (0.67–0.94) | 0.80 | 0.47 | 22 | 7 | 4 | 8 | 0.47 | 0.49 | 41/41 |
| AI analyst, alone | 1.00 (0.84–1.00) | 0.81 (0.62–0.92) | 0.89 | 0.00 | 21 | 0 | 5 | 15 | 0.64 | 0.78 | 41/41 |
| AI analyst, in the system | 1.00 (0.83–1.00) | 0.76 (0.57–0.89) | 0.86 | 0.00 | 19 | 0 | 6 | 15 | 0.74 | 0.85 | 40/41 |
| Rules + classifier (instant) | 1.00 (0.81–1.00) | 0.61 (0.42–0.78) | 0.76 | 0.00 | 16 | 0 | 10 | 15 | 0.44 | 0.54 | 41/41 |
| Full system | 1.00 (0.82–1.00) | 0.69 (0.50–0.83) | 0.82 | 0.00 | 18 | 0 | 8 | 15 | 0.47 | 0.56 | 41/41 |

### synthetic_medium (n = 71; labels {'suspicious': 29, 'safe': 21, 'dangerous': 21})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 1.00 (0.87–1.00) | 0.52 (0.39–0.65) | 0.68 | 0.00 | 26 | 0 | 24 | 21 | 0.48 | 0.51 | 71/71 |
| Text classifier | 0.73 (0.58–0.84) | 0.64 (0.50–0.76) | 0.68 | 0.57 | 32 | 12 | 18 | 9 | 0.37 | 0.37 | 71/71 |
| AI analyst, alone | 1.00 (0.88–1.00) | 0.58 (0.44–0.71) | 0.73 | 0.00 | 29 | 0 | 21 | 21 | 0.59 | 0.63 | 71/71 |
| AI analyst, in the system | 1.00 (0.91–1.00) | 0.76 (0.63–0.86) | 0.86 | 0.00 | 38 | 0 | 12 | 21 | 0.74 | 0.75 | 71/71 |
| Rules + classifier (instant) | 1.00 (0.88–1.00) | 0.56 (0.42–0.69) | 0.72 | 0.00 | 28 | 0 | 22 | 21 | 0.50 | 0.52 | 71/71 |
| Full system | 1.00 (0.89–1.00) | 0.64 (0.50–0.76) | 0.78 | 0.00 | 32 | 0 | 18 | 21 | 0.56 | 0.56 | 71/71 |

### synthetic_hard (n = 38; labels {'safe': 14, 'suspicious': 13, 'dangerous': 11})

| Layer | Precision (95% CI) | Recall (95% CI) | F1 | False-alarm rate | TP | FP | FN | TN | 3-class macro F1 | Exact 3-class accuracy | Covered |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Rules | 0.73 (0.48–0.89) | 0.46 (0.28–0.65) | 0.56 | 0.29 | 11 | 4 | 13 | 10 | 0.36 | 0.42 | 38/38 |
| Text classifier | 0.72 (0.49–0.88) | 0.54 (0.35–0.72) | 0.62 | 0.36 | 13 | 5 | 11 | 9 | 0.40 | 0.42 | 38/38 |
| AI analyst, alone | 0.79 (0.57–0.92) | 0.62 (0.43–0.79) | 0.70 | 0.31 | 15 | 4 | 9 | 9 | 0.50 | 0.51 | 37/38 |
| AI analyst, in the system | 0.81 (0.63–0.92) | 0.92 (0.74–0.98) | 0.86 | 0.36 | 22 | 5 | 2 | 9 | 0.55 | 0.55 | 38/38 |
| Rules + classifier (instant) | 0.73 (0.48–0.89) | 0.46 (0.28–0.65) | 0.56 | 0.29 | 11 | 4 | 13 | 10 | 0.36 | 0.42 | 38/38 |
| Full system | 0.76 (0.57–0.89) | 0.79 (0.59–0.91) | 0.78 | 0.43 | 19 | 6 | 5 | 8 | 0.46 | 0.50 | 38/38 |

## Confusion matrices

**real, Rules** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 3 | 12 | 33 |
| suspicious | 2 | 10 | 121 |
| safe | 4 | 20 | 864 |

**real, Text classifier** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 42 | 2 | 4 |
| suspicious | 101 | 15 | 17 |
| safe | 73 | 180 | 635 |

**real, AI analyst, alone** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 47 | 1 | 0 |
| suspicious | 110 | 16 | 5 |
| safe | 107 | 52 | 715 |

**real, AI analyst, in the system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 43 | 4 | 0 |
| suspicious | 109 | 16 | 8 |
| safe | 78 | 41 | 755 |

**real, Rules + classifier (instant)** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 4 | 28 | 16 |
| suspicious | 2 | 68 | 63 |
| safe | 4 | 26 | 858 |

**real, Full system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 7 | 40 | 1 |
| suspicious | 3 | 120 | 10 |
| safe | 4 | 98 | 786 |

**synthetic, Rules** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 13 | 26 | 11 |
| suspicious | 0 | 14 | 36 |
| safe | 1 | 3 | 46 |

**synthetic, Text classifier** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 24 | 18 | 8 |
| suspicious | 13 | 12 | 25 |
| safe | 10 | 14 | 26 |

**synthetic, AI analyst, alone** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 42 | 4 | 4 |
| suspicious | 10 | 9 | 31 |
| safe | 3 | 1 | 45 |

**synthetic, AI analyst, in the system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 40 | 9 | 0 |
| suspicious | 7 | 23 | 20 |
| safe | 3 | 2 | 45 |

**synthetic, Rules + classifier (instant)** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 14 | 26 | 10 |
| suspicious | 0 | 15 | 35 |
| safe | 1 | 3 | 46 |

**synthetic, Full system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 18 | 31 | 1 |
| suspicious | 0 | 20 | 30 |
| safe | 1 | 5 | 44 |

**real_tr_sms, Rules** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 0 | 3 | 1 |
| suspicious | 1 | 0 | 10 |
| safe | 3 | 13 | 638 |

**real_tr_sms, Text classifier** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 0 | 1 | 3 |
| suspicious | 1 | 4 | 6 |
| safe | 50 | 165 | 439 |

**real_tr_sms, AI analyst, alone** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 3 | 1 | 0 |
| suspicious | 7 | 1 | 3 |
| safe | 79 | 52 | 509 |

**real_tr_sms, AI analyst, in the system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 4 | 0 | 0 |
| suspicious | 7 | 0 | 4 |
| safe | 56 | 32 | 554 |

**real_tr_sms, Rules + classifier (instant)** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 0 | 3 | 1 |
| suspicious | 1 | 0 | 10 |
| safe | 3 | 13 | 638 |

**real_tr_sms, Full system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 0 | 4 | 0 |
| suspicious | 1 | 6 | 4 |
| safe | 3 | 68 | 583 |

**real_en_email, Rules** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 3 | 9 | 32 |
| suspicious | 1 | 10 | 111 |
| safe | 1 | 7 | 226 |

**real_en_email, Text classifier** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 42 | 1 | 1 |
| suspicious | 100 | 11 | 11 |
| safe | 23 | 15 | 196 |

**real_en_email, AI analyst, alone** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 44 | 0 | 0 |
| suspicious | 103 | 15 | 2 |
| safe | 28 | 0 | 206 |

**real_en_email, AI analyst, in the system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 39 | 4 | 0 |
| suspicious | 102 | 16 | 4 |
| safe | 22 | 9 | 201 |

**real_en_email, Rules + classifier (instant)** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 4 | 25 | 15 |
| suspicious | 1 | 68 | 53 |
| safe | 1 | 13 | 220 |

**real_en_email, Full system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 7 | 36 | 1 |
| suspicious | 2 | 114 | 6 |
| safe | 1 | 30 | 203 |

**synthetic_en, Rules** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 4 | 15 | 6 |
| suspicious | 0 | 7 | 18 |
| safe | 1 | 2 | 22 |

**synthetic_en, Text classifier** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 14 | 4 | 7 |
| suspicious | 6 | 2 | 17 |
| safe | 6 | 6 | 13 |

**synthetic_en, AI analyst, alone** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 19 | 3 | 3 |
| suspicious | 1 | 4 | 20 |
| safe | 0 | 0 | 24 |

**synthetic_en, AI analyst, in the system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 19 | 6 | 0 |
| suspicious | 2 | 12 | 11 |
| safe | 1 | 1 | 23 |

**synthetic_en, Rules + classifier (instant)** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 5 | 15 | 5 |
| suspicious | 0 | 8 | 17 |
| safe | 1 | 2 | 22 |

**synthetic_en, Full system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 7 | 18 | 0 |
| suspicious | 0 | 9 | 16 |
| safe | 1 | 2 | 22 |

**synthetic_tr, Rules** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 9 | 11 | 5 |
| suspicious | 0 | 7 | 18 |
| safe | 0 | 1 | 24 |

**synthetic_tr, Text classifier** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 10 | 14 | 1 |
| suspicious | 7 | 10 | 8 |
| safe | 4 | 8 | 13 |

**synthetic_tr, AI analyst, alone** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 23 | 1 | 1 |
| suspicious | 9 | 5 | 11 |
| safe | 3 | 1 | 21 |

**synthetic_tr, AI analyst, in the system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 21 | 3 | 0 |
| suspicious | 5 | 11 | 9 |
| safe | 2 | 1 | 22 |

**synthetic_tr, Rules + classifier (instant)** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 9 | 11 | 5 |
| suspicious | 0 | 7 | 18 |
| safe | 0 | 1 | 24 |

**synthetic_tr, Full system** (rows: label, columns: verdict)

| | dangerous | suspicious | safe |
|---|---:|---:|---:|
| dangerous | 11 | 13 | 1 |
| suspicious | 0 | 11 | 14 |
| safe | 0 | 3 | 22 |
