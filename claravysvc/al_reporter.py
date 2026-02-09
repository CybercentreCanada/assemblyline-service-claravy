import json
from itertools import groupby
from typing import Iterator, List

import claravy.taxonomy as tax
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, ResultSection

from .claravy_client import ClarAVyTag, ClarAVyVerdict
from .corpus import AvKnowledge

CLARAVY_SECTION_ORDER = [
    tax.FAM,
    tax.GRP,
    tax.HEUR,
    tax.VULN,
    tax.CAT,
    tax.FILE,
    tax.PACK,
    tax.PRE,
    tax.SUF,
    tax.UNK,
    tax.NULL,
]


CLARAVY_TAG_CATEGORY = {
    tax.FAM: ("family", 1, "attribution.family"),
    tax.GRP: ("group", 2, "attribution.actor"),
    tax.CAT: ("behavior", 3, "file.behavior"),
    tax.HEUR: ("heuristic", None, "av.heuristic"),
    tax.FILE: ("platform", 4, None),
    tax.PACK: ("packer", 4, None),
    tax.VULN: ("vulnerability", 4, None),
    tax.PRE: ("prefix", None, None),
    tax.SUF: ("suffix", None, None),
    tax.UNK: ("unknown", None, None),
    tax.NULL: ("null", None, None),
}


def _create_tag_section(category: str, tags: Iterator[ClarAVyTag]) -> ResultSection:
    """Creates a `ResultSection` for a list of tags from a single category.

    Result contains table with ClarAVy tag information in descending order by rank.

    Args:
        category: The ClarAVy tag category
        tags: The set of tags within the category.

    Returns:
        A ResultSection summarizing the tags for the specified category.
    """
    tags = sorted(tags, key=lambda t: t.rank, reverse=True)

    category_name, heur_id, tag_type = CLARAVY_TAG_CATEGORY[category]
    tag_table = [
        {
            "name": tag.name,
            "category": category_name,
            "path": tag.path,
            "rank": tag.rank,
        }
        for tag in tags
    ]

    subsection = ResultSection(
        f"ClarAVy extracted {len(tags)} {category_name} tags",
        body=json.dumps(tag_table),
        body_format=BODY_FORMAT.TABLE,
        heuristic=Heuristic(heur_id) if heur_id is not None else None,
    )

    if tag_type is not None:
        for tag in tags:
            subsection.add_tag(tag_type, tag.name)

    return subsection


def _create_category_sections(tags: List[ClarAVyTag]) -> Iterator[ResultSection]:
    """Creates a section for each category of ClarAVy tags.

    Args:
        tags: The set of all ClarAVy tags.

    Yields:
        A ResultSection summarizing the tags for a specific tag category.
    """
    # Sort tags by category for grouping
    tags = sorted(tags, key=lambda t: CLARAVY_SECTION_ORDER.index(t.category))

    for category, category_tags in groupby(tags, key=lambda t: t.category):
        yield _create_tag_section(category, category_tags)


@staticmethod
def _create_result_section(knowledge: AvKnowledge, verdict: ClarAVyVerdict) -> ResultSection:
    """Creates a section summarizing a ClarAVy Verdict.

    Args:
        verdict: The ClarAVy Verdict on the subject file.
        knowledge: The taxonomy used to generate the verdict.

    Returns:
        A ResultSection summarizing the ClarAVy Verdict.
    """
    body = {"is_pup": verdict.is_pup}
    section_tags = dict()

    if verdict.family is not None:
        common_name = verdict.family.lower()

        title = f"ClarAVy identified malware family: {common_name}"
        body["family"] = common_name

        alt_names = list(knowledge.aliases[tax.FAM].get(common_name, []))
        alt_names.sort()

        if alt_names:
            body["aka"] = ", ".join(alt_names)

        section_tags["attribution.family"] = [verdict.family]

        actors = {
            alias
            for tag in verdict.tags
            if tag.category == tax.GRP
            for alias in knowledge.aliases[tax.GRP].get(tag.name, set()) | {tag.name}
        }

        if actors:
            body["actors"] = ", ".join(actors)
            section_tags["attribution.actor"] = actors
    else:
        title = "ClarAVyTag was unable to identify a malware family"

    return ResultSection(
        title,
        json.dumps(body),
        body_format=BODY_FORMAT.KEY_VALUE,
        tags=section_tags,
        heuristic=Heuristic(1) if verdict.family is not None else None,
    )


def generate_claravy_section(knowledge: AvKnowledge, verdict: ClarAVyVerdict) -> ResultSection:
    section = _create_result_section(knowledge, verdict)
    for tag_section in _create_category_sections(verdict.tags):
        section.add_subsection(tag_section)

    return section
