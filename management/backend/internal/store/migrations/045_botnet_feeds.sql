-- 045: botnet command-and-control IP feeds (disabled until switched on)
--   feodo         abuse.ch Feodo Tracker: free, no key.
--   spamhaus_bcl  Spamhaus Botnet Controller List: a Spamhaus subscription;
--                 the api_key column holds the customer's feed URL.
INSERT INTO threat_intel_sources (name, enabled) VALUES
    ('feodo',        FALSE),
    ('spamhaus_bcl', FALSE)
ON CONFLICT (name) DO NOTHING;
