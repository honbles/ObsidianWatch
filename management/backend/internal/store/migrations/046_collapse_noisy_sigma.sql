-- Collapse the backlog of per-process alerts from rules that are now deduplicated per host per day
-- (see sigmaNoisy in detection_engine.go). The newest open alert per host is kept; the rest are closed.
UPDATE alerts SET status = 'closed'
WHERE title = '[Sigma] Execution Of Non-Existing File'
  AND status = 'open'
  AND id NOT IN (
    SELECT max(id) FROM alerts
    WHERE title = '[Sigma] Execution Of Non-Existing File' AND status = 'open'
    GROUP BY host
  );
