from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass

from app.models.entities import Finding


@dataclass(frozen=True)
class ValidationRecipe:
    recipe_id: str
    version: str
    supported_mode: str
    name: str
    safety_description: str
    maximum_step_count: int
    result_vocabulary: tuple[str, ...]

    def normalized(self) -> dict:
        data = asdict(self)
        data["result_vocabulary"] = list(self.result_vocabulary)
        return data


EVIDENCE_REPLAY_RECIPE = ValidationRecipe(
    recipe_id="EVIDENCE-REPLAY-v1",
    version="1.0",
    supported_mode="evidence_replay",
    name="CertShield Evidence Replay",
    safety_description=(
        "Replays evidence already stored on the Finding. It performs no live validation, "
        "requests no certificates, and makes no environment changes."
    ),
    maximum_step_count=100,
    result_vocabulary=(
        "exposure_indicated",
        "evidence_incomplete",
        "no_exposure_indicated",
        "replay_failed",
    ),
)


def recipe_hash(recipe: ValidationRecipe) -> str:
    normalized = json.dumps(recipe.normalized(), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def get_recipe_for_finding(finding: Finding) -> ValidationRecipe:
    _ = finding
    return EVIDENCE_REPLAY_RECIPE
