"""A client for the ClarAVy Python Module which manages aggregating VT3 File scan results."""

import json
import os
import re
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, NamedTuple, Optional, Set

import claravy.taxonomy as tax

from .corpus import AvKnowledge, save_claravy


class ClarAVyTag(NamedTuple):
    name: str
    path: str
    category: str
    rank: int


class ClarAVyVerdict(NamedTuple):
    tags: List[ClarAVyTag]
    is_pup: bool
    family: str


class ClarAVyError(Exception):
    pass


CLARAVY_VERDICT = re.compile(r"^\s*([a-fA-F0-9]+)\s+([0-9]+)\/([0-9]+)\s+([^\r\n]+)$")
CLARAVY_LABEL = re.compile(r"^([A-Z]+):([^|]+)\|([0-9]+\.?[0-9\.]*)\%?$")

DATA_PATH = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "data"))

AVS_PATH = f"{DATA_PATH}/avs.json"
MODEL_PATH = f"{DATA_PATH}/confidence_model.pkl"
IGNORE_PATH = f"{DATA_PATH}/ignore.txt"
SUBSTR_PATH = f"{DATA_PATH}/substr.txt"


def _parse_claravy_result(pup_tags: Set[str], file: str) -> Optional[ClarAVyVerdict]:
    try:
        with open(file, "r") as f:
            result = f.read().strip()
    except FileNotFoundError:
        result = None

    if not result:
        return None

    entry = CLARAVY_VERDICT.match(result)

    if not entry:
        return None

    label_list = entry.group(4).split(",")

    family_confidence = 0
    family_name = None
    is_pup = False

    tags: List[ClarAVyTag] = []

    for label in label_list:
        parsed = CLARAVY_LABEL.match(label.strip())

        if not parsed:
            continue

        category, name, confidence = parsed.group(1), parsed.group(2), parsed.group(3)

        if category == tax.FAM:
            conf = float(confidence)

            if conf > family_confidence:
                family_confidence = conf
                family_name = name
        else:
            tag = f"{category}:{name}"
            is_pup |= tag.lower() in pup_tags
            tags.append(ClarAVyTag(name, tag, category, confidence))

    if not family_name:
        return None

    tags.sort(key=lambda x: x.rank, reverse=True)

    return ClarAVyVerdict(tags, is_pup, family_name)


def generate_claravy_verdict(file: Dict[str, Any], knowledge: AvKnowledge) -> Optional[ClarAVyVerdict]:
    """Invokes ClarAVy on the provided VT3 File Object with the provided Taxonomy index.

    Args:
        file: VT3 File
        knowledge: Data-set to use for taxonomy and aliases

    Returns:
        Identified ClarAVy detection verdict or None if not detected.

    Raises:
        ClarAVyError: If the ClarAVy process fails to process the same or there is an error parsing output.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        input_alias = f"{temp_dir}/alias"
        input_taxonomy = f"{temp_dir}/taxonomy"

        input_scan = f"{temp_dir}/input"
        output_result = f"{temp_dir}/output"

        with open(input_scan, "w") as f:
            f.write(json.dumps({"data": file}))

        save_claravy(knowledge, input_taxonomy, input_alias)

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "claravy.avtagger",
                "-f",
                input_scan,
                "-o",
                output_result,
                "-al",
                input_alias,
                "-av",
                AVS_PATH,
                "-tax",
                input_taxonomy,
                "-su",
                SUBSTR_PATH,
                "-cm",
                MODEL_PATH,
                "-bl",
                IGNORE_PATH,
            ],
            capture_output=False,
            text=True,
        )

        if result.returncode != 0:
            raise ClarAVyError(f"ClarAVy failed with result code: {result.returncode}")

        return _parse_claravy_result(knowledge.pup_tags, output_result)
