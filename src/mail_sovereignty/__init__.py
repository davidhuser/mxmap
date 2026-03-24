"""Mail Sovereignty Classifier — public API."""

from .classifier import classify, classify_many
from .models import ClassificationResult, Evidence, Provider, SignalKind

__all__ = [
    "classify",
    "classify_many",
    "ClassificationResult",
    "Evidence",
    "Provider",
    "SignalKind",
]
