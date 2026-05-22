MERGE INTO profiles KEY(subject) VALUES (
    'alice@quantumbank.local',
    'Alice Quantum',
    'alice@quantumbank.local',
    '+55 71 90000-0001',
    '123.456.789-00',
    'Av. Oceano Seguro, 100 - Salvador, BA',
    TIMESTAMP '2026-05-22 10:00:00'
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
