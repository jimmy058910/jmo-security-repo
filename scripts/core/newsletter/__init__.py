"""JMo newsletter content-assembly package.

Public API:

- ``generate_draft`` — build a newsletter draft (HTML + plain text) from
  CHANGELOG release notes, an optional customer story, and the shared HTML
  template.
- ``NewsletterDraft`` — dataclass holding the assembled subject/HTML/text.

The companion module :mod:`scripts.core.newsletter_broadcast` is responsible
for uploading the assembled HTML to Resend as a broadcast draft. The two
modules are intentionally decoupled so that content review (this package) and
broadcast plumbing (Resend) can move independently.
"""

from scripts.core.newsletter.draft_generator import (
    NewsletterDraft,
    ReleaseEntry,
    generate_draft,
)

__all__ = ["NewsletterDraft", "ReleaseEntry", "generate_draft"]
