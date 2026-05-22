MERGE INTO profiles KEY(subject) VALUES (
    'alice@quantumbank.local',
    'Alice Quantum',
    'alice@quantumbank.local',
    '+55 71 90000-0001',
    '123.456.789-00',
    'Av. Oceano Seguro, 100 - Salvador, BA',
    TIMESTAMP '2026-05-22 10:00:00'
);

MERGE INTO profiles KEY(subject) VALUES (
    'service-account-quantum-bank-test',
    'Quantum Bank Smoke Runner',
    'smoke@quantumbank.local',
    '+55 71 90000-0600',
    '000.000.000-60',
    'Rua Smoke E2E, 600 - Salvador, BA',
    TIMESTAMP '2026-05-22 10:06:00'
);

MERGE INTO profiles KEY(subject) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Alice Quantum',
    'alice@quantumbank.local',
    '+55 71 90000-0001',
    '123.456.789-00',
    'Av. Oceano Seguro, 100 - Salvador, BA',
    TIMESTAMP '2026-05-22 10:01:00'
);

MERGE INTO profiles KEY(subject) VALUES (
    'quantum-bank-test',
    'Quantum Bank Local Test Client',
    'quantum-bank-test@quantumbank.local',
    '+55 71 90000-0601',
    '000.000.000-61',
    'Rua Cliente Local, 601 - Salvador, BA',
    TIMESTAMP '2026-05-22 10:07:00'
);

MERGE INTO statement_entries KEY(id) VALUES (
    1,
    'alice@quantumbank.local',
    TIMESTAMP '2026-05-20 09:30:00',
    'Pix recebido - Cafeteria Horizonte',
    125.50,
    'CREDIT'
);

MERGE INTO statement_entries KEY(id) VALUES (
    2,
    'alice@quantumbank.local',
    TIMESTAMP '2026-05-21 14:15:00',
    'Pix enviado - Mercado Central',
    -42.90,
    'DEBIT'
);

MERGE INTO statement_entries KEY(id) VALUES (
    3,
    'service-account-quantum-bank-test',
    TIMESTAMP '2026-05-22 15:03:00',
    'Smoke E2E balance check',
    603.00,
    'CREDIT'
);

MERGE INTO statement_entries KEY(id) VALUES (
    4,
    '00000000-0000-0000-0000-000000000001',
    TIMESTAMP '2026-05-22 15:04:00',
    'Alice smoke E2E statement',
    604.00,
    'CREDIT'
);

MERGE INTO statement_entries KEY(id) VALUES (
    5,
    'quantum-bank-test',
    TIMESTAMP '2026-05-22 15:05:00',
    'Local test client smoke E2E statement',
    605.00,
    'CREDIT'
);
