# cvss_metrics.py

# Словник метрик
metrics = {
    # Base Metrics
    'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},      # Attack Vector: Network, Adjacent, Local, Physical
    'AC': {'L': 0.77, 'H': 0.44},                             # Attack Complexity: Low, High
    'PR': {'N': 0.85, 'L': 0.62, 'H': 0.27},                  # Privileges Required: None, Low, High
    'UI': {'N': 0.85, 'R': 0.62},                             # User Interaction: None, Required
    'S':  {'U': 0.55, 'C': 0.85},                             # Scope: Unchanged, Changed
    'C':  {'N': 0.0,  'L': 0.22, 'H': 0.56},                 # Confidentiality: None, Low, High
    'I':  {'N': 0.0,  'L': 0.22, 'H': 0.56},                 # Integrity: None, Low, High
    'A':  {'N': 0.0,  'L': 0.22, 'H': 0.56},                 # Availability: None, Low, High

    # Temporal Metrics
    'E':  {'X': 1.0, 'H': 1.0, 'F': 0.97, 'P': 0.94, 'U': 0.91},  # Exploit Code Maturity: Not Defined, High, Functional, Proof-of-Concept, Unproven
    'RL': {'X': 1.0, 'U': 1.0, 'W': 0.97, 'T': 0.96, 'O': 0.95},  # Remediation Level: Not Defined, Unavailable, Workaround, Temporary Fix, Official Fix
    'RC': {'X': 1.0, 'C': 1.0, 'R': 0.96, 'U': 0.92},              # Report Confidence: Not Defined, Confirmed, Reasonable, Unknown

    # Environmental Metrics
    'MAV': {'X': None, 'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},  # Modified Attack Vector: [X, N, A, L, P] - X означає "Not Defined" (використовувати значення з базових AV)
    'MAC': {'X': None, 'L': 0.77, 'H': 0.44},                       # Modified Attack Complexity: [X, L, H]
    'MPR': {'X': None, 'N': 0.85, 'L': 0.62, 'H': 0.27},            # Modified Privileges Required: [X, N, L, H]
    'MUI': {'X': None, 'N': 0.85, 'R': 0.62},                       # Modified User Interaction: [X, N, R]
    'MS':  {'X': None, 'U': 0.55, 'C': 0.85},                       # Modified Scope: [X, U (Unchanged), C (Changed)] – якщо не визначено (X), використовується базовий S
    'MC':  {'X': None, 'N': 0.0, 'L': 0.22, 'H': 0.56},             # Modified Confidentiality: [X, N, L, H]
    'MI':  {'X': None, 'N': 0.0, 'L': 0.22, 'H': 0.56},             # Modified Integrity: [X, N, L, H]
    'MA':  {'X': None, 'N': 0.0, 'L': 0.22, 'H': 0.56},             # Modified Availability: [X, N, L, H]

    # Environmental Requirements
    'CR':  {'X': 1.0, 'L': 0.5, 'M': 1.0, 'H': 1.5},               # Confidentiality Requirement: Not Defined, Low, Medium, High
    'IR':  {'X': 1.0, 'L': 0.5, 'M': 1.0, 'H': 1.5},               # Integrity Requirement: Not Defined, Low, Medium, High
    'AR':  {'X': 1.0, 'L': 0.5, 'M': 1.0, 'H': 1.5}                # Availability Requirement: Not Defined, Low, Medium, High
}

# Словник описів метрик
descriptions = {
    'AV': {'N': 'Мережа', 'A': 'Атака через мережу', 'L': 'Локальна атака', 'P': 'Фізична атака'},
    'AC': {'L': 'Низька складність', 'H': 'Висока складність'},
    'PR': {'N': 'Не потрібні права', 'L': 'Низькі права', 'H': 'Високі права'},
    'UI': {'N': 'Не потрібна взаємодія', 'R': 'Потрібна взаємодія'},
    'S': {'U': 'Не змінюється', 'C': 'Змінюється'},
    'C': {'N': 'Немає впливу', 'L': 'Низький вплив', 'H': 'Високий вплив'},
    'I': {'N': 'Немає впливу', 'L': 'Низький вплив', 'H': 'Високий вплив'},
    'A': {'N': 'Немає впливу', 'L': 'Низький вплив', 'H': 'Високий вплив'},
    'E': {'X': 'Не визначено', 'U': 'Малоймовірний', 'F': 'Ймовірний', 'P': 'Дуже ймовірний', 'H': 'Високий'},
    'RL': {'X': 'Не визначено', 'U': 'Малоймовірний', 'W': 'Ймовірний', 'T': 'Дуже ймовірний'},
    'RC': {'X': 'Не визначено', 'U': 'Малоймовірний', 'R': 'Ймовірний', 'C': 'Підтверджений'},
    'MAV': {'N': 'Мережа', 'A': 'Атака через мережу', 'P': 'Фізична атака'},
    'CR': {'X': 'Не визначено', 'L': 'Низький вплив', 'M': 'Середній вплив', 'H': 'Високий вплив'},
    'IR': {'X': 'Не визначено', 'L': 'Низький вплив', 'M': 'Середній вплив', 'H': 'Високий вплив'},
    'AR': {'X': 'Не визначено', 'L': 'Низький вплив', 'M': 'Середній вплив', 'H': 'Високий вплив'}
}
ukrainian_labels = {
    'AV': 'Вектор атаки',
    'AC': 'Складність атаки',
    'PR': 'Права доступу',
    'UI': 'Взаємодія користувача',
    'S': 'Вплив',
    'C': 'Конфіденційність',
    'I': 'Цілісність',
    'A': 'Доступність',
    'E': 'Досвідченість',
    'RL': 'Рівень ремедіації',
    'RC': 'Рівень достовірності',
    'MAV': 'Модиф. вектор атаки',
    'MAC': 'Модиф. складність атаки',
    'MPR': 'Модиф. права доступу',
    'MUI': 'Модиф. взаємодія користувача',
    'MS': 'Модиф. вплив',
    'MC': 'Модиф. конфіденційність',
    'MI': 'Модиф. цілісність',
    'MA': 'Модиф. доступність',
    'CR': 'Вимога конфіденційності',
    'IR': 'Вимога цілісності',
    'AR': 'Вимога доступності'
}

metric_patterns = {
    'AV': r'AV:([NPAL])',
    'AC': r'AC:([LH])',
    'PR': r'PR:([NLH])',
    'UI': r'UI:([NR])',
    'S': r'S:([UC])',
    'C': r'C:([NLH])',
    'I': r'I:([NLH])',
    'A': r'A:([NLH])',
    'E': r'E:([XUFPH])',
    'RL': r'RL:([XUWTO])',
    'RC': r'RC:([XURC])',
    'MAV': r'MAV:([NAP])',
    'MAC': r'MAC:([LH])',
    'MPR': r'MPR:([NLH])',
    'MUI': r'MUI:([NR])',
    'MS': r'MS:([UC])',
    'MC': r'MC:([NLH])',
    'MI': r'MI:([NLH])',
    'MA': r'MA:([NLH])',
    'CR': r'CR:([XLMH])',
    'IR': r'IR:([XLMH])',
    'AR': r'AR:([XLMH])'
}

