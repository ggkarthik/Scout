DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'component_vulnerability_states'
      AND column_name = 'trace_json'
      AND udt_name = 'oid'
  ) THEN
    ALTER TABLE public.component_vulnerability_states
      ALTER COLUMN trace_json TYPE TEXT
      USING CASE
        WHEN trace_json IS NULL THEN NULL
        ELSE convert_from(lo_get(trace_json), 'UTF8')
      END;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'finding_events'
      AND column_name = 'details_json'
      AND udt_name = 'oid'
  ) THEN
    ALTER TABLE public.finding_events
      ALTER COLUMN details_json TYPE TEXT
      USING CASE
        WHEN details_json IS NULL THEN NULL
        ELSE convert_from(lo_get(details_json), 'UTF8')
      END;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'findings'
      AND column_name = 'evidence'
      AND udt_name = 'oid'
  ) THEN
    ALTER TABLE public.findings
      ALTER COLUMN evidence TYPE TEXT
      USING CASE
        WHEN evidence IS NULL THEN NULL
        ELSE convert_from(lo_get(evidence), 'UTF8')
      END;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'findings'
      AND column_name = 'precedence_trace'
      AND udt_name = 'oid'
  ) THEN
    ALTER TABLE public.findings
      ALTER COLUMN precedence_trace TYPE TEXT
      USING CASE
        WHEN precedence_trace IS NULL THEN NULL
        ELSE convert_from(lo_get(precedence_trace), 'UTF8')
      END;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'sbom_uploads'
      AND column_name = 'evidence_json'
      AND udt_name = 'oid'
  ) THEN
    ALTER TABLE public.sbom_uploads
      ALTER COLUMN evidence_json TYPE TEXT
      USING CASE
        WHEN evidence_json IS NULL THEN NULL
        ELSE convert_from(lo_get(evidence_json), 'UTF8')
      END;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'vulnerabilities'
      AND column_name = 'references_json'
      AND udt_name = 'oid'
  ) THEN
    ALTER TABLE public.vulnerabilities
      ALTER COLUMN references_json TYPE TEXT
      USING CASE
        WHEN references_json IS NULL THEN NULL
        ELSE convert_from(lo_get(references_json), 'UTF8')
      END;
  END IF;
END $$;
