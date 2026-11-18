"""CLI entrypoint for generating N170 Verify truth specimens."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from n170_verify.specimens.generator import (
    DEFAULT_SPECIMEN_SEED_HEX,
    generate_specimens,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate N170 Verify truth specimens and key registry."
    )
    parser.add_argument(
        "--seed",
        default=None,
        help="64-hex deterministic generation seed (defaults to N170_VERIFY_SPECIMEN_SEED_HEX or built-in default)",
    )
    parser.add_argument(
        "--repo-root",
        default=None,
        help="Path to repository root where examples/ and web/ live",
    )

    args = parser.parse_args(argv)

    seed = args.seed or os.environ.get("N170_VERIFY_SPECIMEN_SEED_HEX", DEFAULT_SPECIMEN_SEED_HEX)
    repo_root = Path(args.repo_root) if args.repo_root else Path.cwd()

    result = generate_specimens(seed_hex=seed, output_repo_root=repo_root)

    print(f"Generated truth specimens successfully with seed: {result.seed_hex}")
    print(f"  Specimen S1 proof_id: {result.bundle_s1.proof_id}")
    print(f"  Offline specimen proof_id: {result.bundle_offline.proof_id}")
    print(f"  Registry updated_at: {result.registry.updated_at_utc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
