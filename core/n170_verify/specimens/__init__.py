"""N170 Verify truth specimens and deterministic generation tools."""

from n170_verify.specimens.generator import (
    DEFAULT_SPECIMEN_SEED_HEX,
    SpecimenGenerationResult,
    generate_specimens,
)

__all__ = [
    "DEFAULT_SPECIMEN_SEED_HEX",
    "SpecimenGenerationResult",
    "generate_specimens",
]
