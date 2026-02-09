"""A module to handle loading, saving and consolidating AV Knowledge (taxonomy , aliases, actors)."""

import json
import re
from copy import deepcopy
from functools import reduce
from typing import Dict, NamedTuple, Optional, Set, TypeAlias

import claravy.taxonomy as tax

CLARAVY_CATEGORY = re.compile(r"^\[([^\[]+)\]$")

Taxonomy: TypeAlias = Dict[str, Set[str]]
AliasMap: TypeAlias = Dict[str, Dict[str, Set[str]]]


class AvKnowledge(NamedTuple):
    taxonomy: Taxonomy
    aliases: AliasMap
    pup_tags: Set[str]


CLARAVY_TAGS = [
    tax.FAM,
    tax.GRP,
    tax.FILE,
    tax.CAT,
    tax.PACK,
    tax.VULN,
    tax.PRE,
    tax.SUF,
    tax.HEUR,
    tax.UNK,
    tax.NULL,
]


def _clean_name(name: str) -> str:
    return re.sub(r"[\[\]\s]", "", name).lower()


def _save_claravy_taxonomy(file: str, taxonomy: Taxonomy):
    with open(file, "w") as f:
        for k, v in taxonomy.items():
            if not v:
                continue

            f.write(f"[{k}]\n")
            f.write("\n".join(v))
            f.write("\n\n")


def _load_claravy_taxonomy(file: Optional[str]) -> Taxonomy:
    taximony = {k: set() for k in CLARAVY_TAGS}

    if not file:
        return taximony

    with open(file, "r") as f:
        category = None
        for line in f:
            line = line.strip()

            if not line:
                continue

            cat_decl = CLARAVY_CATEGORY.match(line)

            if cat_decl:
                category = cat_decl.group(1)
                taximony[category] = set()
                continue

            if not category:
                continue

            taximony[category].add(line)

    return taximony


def _load_claravy_alias(file: Optional[str]) -> AliasMap:
    alias_mapping = {k: dict() for k in CLARAVY_TAGS}

    if not file:
        return alias_mapping

    category = None

    with open(file, "r") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            category_decl = CLARAVY_CATEGORY.match(line)

            if category_decl:
                category = category_decl.group(1)
                alias_mapping[category] = {}
                continue

            if not category:
                continue

            name, alias = line.split("\t")

            if alias not in alias_mapping[category]:
                alias_mapping[category][alias] = set()

            alias_mapping[category][alias].add(name)

    return alias_mapping


def _save_claravy_alias(file: Optional[str], alias_mapping: AliasMap):
    with open(file, "w") as f:
        for category, aliases in alias_mapping.items():
            if not aliases:
                continue

            f.write(f"[{category}]\n")

            entries = [(a, canonical_name) for canonical_name, syn in aliases.items() for a in syn]

            if not entries:
                continue

            f.write("\n".join([f"{a}\t{canonical_name}" for a, canonical_name in entries]))

            f.write("\n\n")


def _load_malpedia_alias(malpedia_families: str, malpedia_actors: str):
    with (
        open(malpedia_actors, "r") as f_actors,
        open(malpedia_families, "r") as f_families,
    ):
        alias_mapping = {k: dict() for k in CLARAVY_TAGS}
        families = json.load(f_families)
        actors = json.load(f_actors)

        for _, details in families.items():
            name = _clean_name(details["common_name"])

            if "." in name:
                name = ".".join(name.split(".")[1:])

            aliases = set(_clean_name(a) for a in details.get("alt_names", []))

            if not aliases:
                continue

            if name not in alias_mapping[tax.FAM]:
                alias_mapping[tax.FAM][name] = set()

            alias_mapping[tax.FAM][name] |= aliases

        # Malpedia will assign an alias to multiple different common names. This is incompatible with ClarAVys
        # one to one model, so to map the Malpedia dataset we drop repeated mappings to different aliases.
        aliases_assigned_common_name = set()
        for name, details in actors.items():
            if "meta" not in details:
                continue

            aliases = set(_clean_name(s) for s in details["meta"].get("synonyms", []))

            aliases.difference_update(aliases_assigned_common_name)

            aliases_assigned_common_name |= aliases

            if not aliases:
                continue

            name = _clean_name(name)

            if name not in alias_mapping[tax.GRP]:
                alias_mapping[tax.GRP][name] = set()

            alias_mapping[tax.GRP][name] |= aliases

        return alias_mapping


def _sanitize_family_conflict_to_group(
    families: Set[str], family_alias: Dict[str, Set[str]], taxonomy: Set[str], alias: Dict[str, Set[str]]
) -> None:
    # All common names that are identified as groups and families
    collision_names = taxonomy.intersection(families)

    group_alias = reduce(lambda a, b: a | b, alias.values(), set())
    taxonomy.difference_update(group_alias)

    taxonomy.difference_update(collision_names)

    for c in collision_names:
        if c not in alias:
            continue

        new_aliases = family_alias.get(c, set()) | alias[c]

        family_alias[c] = new_aliases
        families |= new_aliases

        alias.pop(c)

    # Drop group alises that intersect family names
    for aliases in alias.values():
        aliases.difference_update(families)


def _sanitize_claravy(source: AvKnowledge) -> AvKnowledge:
    taxonomy = deepcopy(source.taxonomy)
    alias = deepcopy(source.aliases)

    # ClarAVy requires that if a name if identified as a family it does not also get identified as a group.
    # We give families precedence over token names
    families = taxonomy[tax.FAM] | reduce(lambda a, b: a | b, alias[tax.FAM].values(), set())

    # Resolve name conflicts between families and other token groups. Family name takes precedence
    for g in CLARAVY_TAGS:
        if g == tax.FAM:
            continue

        _sanitize_family_conflict_to_group(families, alias[tax.FAM], taxonomy[g], alias[g])

    # Malpedia will include alises in the common_name which can cause common_name to occur as both an alias and
    # the taxonomy. ClarAVy does not support this, so we truncate alias values from the taxonomy
    for g, tokens in taxonomy.items():
        group_alias = reduce(lambda a, b: a | b, alias[g].values(), set())

        redundant = group_alias.intersection(tokens)

        if redundant:
            tokens.difference_update(redundant)

    return AvKnowledge(taxonomy, alias, source.pup_tags)


def _load_malpedia_taxonomy(malpedia_families: str, malpedia_actors: str):
    with (
        open(malpedia_actors, "r") as f_actors,
        open(malpedia_families, "r") as f_families,
    ):
        families = json.load(f_families)
        actors = json.load(f_actors)

        taxonomy = {k: set() for k in CLARAVY_TAGS}

        for path in families.keys():
            name = _clean_name(path.split(".")[1])

            if name.startswith("unidentified"):
                continue

            taxonomy[tax.FAM].add(name)

        for slug, details in actors.items():
            name = _clean_name(details.get("value", slug))
            taxonomy[tax.GRP].add(name)

        return taxonomy


def _load_pup_index(file: str) -> Set[str]:
    with open(file, "r") as f:
        return set([line.strip().lower() for line in f if line.strip()])


def load_claravy(taxonomy: str, alias: str, pup_index: str) -> AvKnowledge:
    """Loads ClarAVy taxonomy.

    Args:
        taxonomy: The file containing ClarAVy taxonomy.
        alias: The file containing ClarAVy alias.
        pup_index: Location of file containing tags that define pup.

    Returns:
        A knowledge object containing taxonomy and alias.
    """
    return AvKnowledge(_load_claravy_taxonomy(taxonomy), _load_claravy_alias(alias), _load_pup_index(pup_index))


def load_malpedia(families: str, actors: str) -> AvKnowledge:
    """Loads Malpedia taxonomy.

    Args:
        families: Malpedia family index.
        actors: Malpedia actor index.

    Returns:
        A knowledge object containing families and actors.
    """
    taxonomy = _load_malpedia_taxonomy(families, actors)
    alias = _load_malpedia_alias(families, actors)

    return _sanitize_claravy(AvKnowledge(taxonomy, alias, set()))


def save_claravy(knowledge: AvKnowledge, taxonomy: str, alias: str):
    """Saved ClarAVy knowledge to file.

    Args:
        knowledge: The knowledge to save to file.
        taxonomy: The ClarAVy taxonomy destination path.
        alias: The ClarAVy alias destination path.
    """
    _save_claravy_alias(alias, knowledge.aliases)
    _save_claravy_taxonomy(taxonomy, knowledge.taxonomy)


def _consolidate_group_alias(truth: Dict[str, Set[str]], auxiliary: Dict[str, Set[str]]) -> Dict[str, Set[str]]:
    result: Dict[str, Set[str]] = deepcopy(truth)

    truth_aliases = reduce(lambda a, b: a | b, truth.values(), set())
    truth_common = set(truth.keys())

    for common, aliases in auxiliary.items():
        if common in truth_aliases or common in truth_common:
            continue

        aliases.discard(truth_aliases)

        if aliases:
            truth_common.add(common)
            truth_aliases |= aliases

            result[common] = aliases

    return result


def _consolidate_group_taxonomy(truth: Set[str], auxiliary: Set[str], aliases: Dict[str, Set[str]]) -> Set[str]:
    # Consolidate all common names and then aliases to the common names
    aliased_names = reduce(lambda a, b: a | b, aliases.values(), set())

    return truth.union(auxiliary.difference(aliased_names))


def consolidate_knowledge(truth: AvKnowledge, auxiliary: AvKnowledge) -> AvKnowledge:
    """Consolidates two knowledges sources with presedence over a truth knowledge set.

    Args:
        truth: Truth knowledge set
        auxiliary: Auxiliary knowledge set

    Returns:
        A knowledge set containing both the auxiliary and truth knowledge.
    """
    alias = {g: _consolidate_group_alias(truth.aliases[g], auxiliary.aliases[g]) for g in CLARAVY_TAGS}
    taxonomy = {
        g: _consolidate_group_taxonomy(truth.taxonomy[g], auxiliary.taxonomy[g], alias[g]) for g in CLARAVY_TAGS
    }

    return _sanitize_claravy(AvKnowledge(taxonomy, alias, truth.pup_tags | auxiliary.pup_tags))
