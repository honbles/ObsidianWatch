-- Saved searches were stored as the Events page's chip labels ("OS: windows Type: process Severity: 4"),
-- which do not parse as a query. Rewrite them into the query language (same rules as NormalizeSavedQuery).
UPDATE saved_event_queries SET query =
  regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(regexp_replace(query,
    '(^|\s)OS: (\S+)', '\1os:\2', 'gi'),
    '(^|\s)Type: (\S+)', '\1type:\2', 'gi'),
    '(^|\s)Severity: ([1-5])', '\1sev>=\2', 'gi'),
    '(^|\s)IP: (\S+)', '\1ip:\2', 'gi'),
    '(^|\s)Port: (\d+)', '\1port:\2', 'gi'),
    '(^|\s)Proto: (\S+)', '\1proto:\2', 'gi'),
    '(^|\s)Source: (\S+)', '\1source:\2', 'gi'),
    '(^|\s)Host: (\S+)', '\1host:\2', 'gi')
WHERE query ~* '(^|\s)(OS|Type|Severity|IP|Port|Proto|Source|Host): ';
