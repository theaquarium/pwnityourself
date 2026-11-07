"""Lesson registry for PIY.

Each lesson is a module in this package exposing:
  SLUG, APP_NAME, SANDBOX_TIMEOUT
  build_image() -> modal.Image     (the vulnerable target + tooling)
  build_lesson() -> dict           (the notebook content)
  summary()     -> dict            (index-card metadata)

Adding a new exploit lab is just dropping a new module here and listing it in
_MODULES below.
"""
from . import log4shell, sshhole, phpcgi

_MODULES = [log4shell, sshhole, phpcgi]

LESSONS = {m.SLUG: m for m in _MODULES}


def list_summaries() -> list[dict]:
    return [m.summary() for m in _MODULES]


def get_module(slug: str):
    return LESSONS.get(slug)
