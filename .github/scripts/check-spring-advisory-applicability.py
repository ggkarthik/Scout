#!/usr/bin/env python3
"""Invalidate the Spring scan exceptions when their absent-feature premise changes."""
from pathlib import Path
import re


# Include wildcard imports, fully qualified names, reflective class names, and resources.
# Conservatively require renewed review for any server-side view or SSE implementation.
REVIEW_REQUIRED = re.compile(
    r"Xslt|XSLT|\.xslt?\b|web\.servlet\.view|web\.reactive\.result\.view|"
    r"ViewResolver|ModelAndView|FragmentsRendering|SseEmitter|ServerSentEvent|"
    r"ResponseBodyEmitter|text/event-stream|TEXT_EVENT_STREAM|"
    r"addViewController|addViewControllers|configureViewResolvers|@Controller\b"
)


def check_source(source: str) -> bool:
    return REVIEW_REQUIRED.search(source) is None


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    violations = []
    for path in (root / "prototype-app/backend/src/main").rglob("*"):
        if path.is_file() and not check_source(path.read_text(errors="replace")):
            violations.append(str(path.relative_to(root)))
    if violations:
        raise SystemExit(
            "Reassess/remove the CVE-2026-47884 and CVE-2026-47890 exceptions before "
            "adding view rendering or SSE features:\n" + "\n".join(violations)
        )
    print("Spring advisory applicability: no server-side view rendering or SSE features")


if __name__ == "__main__":
    main()
