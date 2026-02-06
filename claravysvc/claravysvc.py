"""A service which consumes Anti-Virus tags (`av.virus_name`) and extracts family, behaviour and platform.

The service leverages by[ClarAVy](https://github.com/FutureComputing4AI/ClarAVy) to
identify family, behaviour and platform identifiers from Anti-virus tags.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from collections import namedtuple
from functools import reduce
from itertools import groupby
from pathlib import Path
from typing import Any, AnyStr, Dict, Iterator, List, NamedTuple, Optional, Set

import claravy.taxonomy as tax
from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection

from claravysvc.corpus import (
    AvKnowledge,
    consolidate_knowledge,
    load_claravy,
    load_malpedia,
    load_pup_index,
    save_claravy,
)

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

CLARAVY_VERDICT = re.compile(r"^\s*([a-fA-F0-9]+)\s+([0-9]+)\/([0-9]+)\s+([^\r\n]+)$")
CLARAVY_LABEL = re.compile(r"^([A-Z]+):([^|]+)\|([0-9]+\.?[0-9\.]*)\%?$")


DATA_PATH = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "data"))


class ClarAVyTag(NamedTuple):
    name: str
    path: str
    category: str
    rank: int


class ClarAVyVerdit(NamedTuple):
    tags: List[ClarAVyTag]
    is_pup: bool
    family: str


class ClaravySvc(ServiceBase):
    """A service which consumes Anti-Virus tags (`av.virus_name`) and extracts family, behaviour and platform.

    The service leverages by[ClarAVy](https://github.com/FutureComputing4AI/ClarAVy) to
    identify family, behaviour and platform identifiers from Anti-virus tags.
    """

    VT3_FILE_SOURCE_ATTR = ("virus_scan_vt3_files", "virus_total_vt3_files")

    ALIAS_PATH = f"{DATA_PATH}/aliases.txt"
    AVS_PATH = f"{DATA_PATH}/avs.json"
    MODEL_PATH = f"{DATA_PATH}/confidence_model.pkl"
    IGNORE_PATH = f"{DATA_PATH}/ignore.txt"
    SUBSTR_PATH = f"{DATA_PATH}/substr.txt"
    TAXONOMY_PATH = f"{DATA_PATH}/taxonomy.txt"
    PUP_PATH = f"{DATA_PATH}/pup.txt"

    MAL_FAM_PATH = f"{DATA_PATH}/malpedia-families.json"
    MAL_ACTOR_PATH = f"{DATA_PATH}/malpedia-actors.json"

    def __init__(self, config):
        super().__init__(config)
        self.base_knowledge: AvKnowledge = AvKnowledge({}, {})
        self.malpedia_knowledge: AvKnowledge = AvKnowledge({}, {})
        self.pup_tags: Set[str] = set()

    def start(self) -> None:
        self.base_knowledge = load_claravy(ClaravySvc.TAXONOMY_PATH, ClaravySvc.ALIAS_PATH)

        # Consolidate the malpedia and base knowledge for scan setting "Use Malpedia"; this will consider
        # malpedia the ground truth if any conflicts arise.
        self.malpedia_knowledge = ClaravySvc.load_malpedia(
            self.base_knowledge, ClaravySvc.MAL_FAM_PATH, ClaravySvc.MAL_ACTOR_PATH
        )

        self.pup_tags = load_pup_index(ClaravySvc.PUP_PATH)

    @staticmethod
    def load_malpedia(auxiliary_knowledge: AvKnowledge, family: str, actor: str) -> AvKnowledge:
        malpedia_knowledge = load_malpedia(family, actor)

        return consolidate_knowledge(malpedia_knowledge, auxiliary_knowledge)

    def _load_rules(self) -> None:
        """Load Malpedia families file. This function will check the updates directory and try to load the latest
        Malpedia families file. If not successful, it will try older versions of the Malpedia families file.
        """
        try:
            rules = self.rules_list

            families = [r for r in rules if "malpedia_families" in r and r.lower().endswith(".json")]
            agents = [r for r in rules if "malpedia_actors" in r and r.lower().endswith(".json")]

            if len(families) != 1 or len(agents) == 1:
                self.log.error("ClarAVy didn't process the Malpedia file. Check if the service can reach the updater.")
                return

            self.malpedia_knowledge = ClaravySvc.load_malpedia_knowledge(self.base_knowledge, families[0], agents[0])

        except Exception as e:
            self.log.error(f"Error updating malpedia knowledge base. Reason: {e}")

    def _parse_claravy_result(self, file: str) -> ClarAVyVerdit:
        try:
            with open(file, "r") as f:
                result = f.read().strip()
        except FileNotFoundError:
            result = None

        if not result:
            self.log.info("No results produced by ClarAVy.")
            return None

        entry = CLARAVY_VERDICT.match(result)

        if not entry:
            self.log.error(f"ClarAVy result did not match expected output pattern. Parse error on results: {result}")
            return None

        label_list = entry.group(4).split(",")

        family_confidence = 0
        family_name = None
        is_pup = False

        tags: List[ClarAVyTag] = []

        for label in label_list:
            parsed = CLARAVY_LABEL.match(label.strip())

            if not parsed:
                self.log.error(f'Error parsing label: "{label}"; ignoring.')
                continue

            category, name, confidence = parsed.group(1), parsed.group(2), parsed.group(3)

            if category == tax.FAM:
                conf = float(confidence)

                if conf > family_confidence:
                    family_confidence = conf
                    family_name = name
            else:
                tag = f"{category}:{name}"
                is_pup |= tag.lower() in self.pup_tags
                tags.append(ClarAVyTag(name, tag, category, confidence))

        if not family_name:
            self.log.error("Family label is missing. Skipping ClarAVy result.")
            return None

        tags.sort(key=lambda x: x.rank, reverse=True)

        return ClarAVyVerdit(tags, is_pup, family_name)

    def _generate_verdict(self, file: Dict[str, Any], knowledge: AvKnowledge) -> Optional[ClarAVyVerdit]:
        """Gets AVClass tags from a list of AV labels.

        Args:
            file: VT3 File
            knowledge: Data-set to use for taxonomy and aliases

        Returns:
            Identified ClarAVy detection verdict or None if not detected.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            input_alias = f"{temp_dir}/alias"
            input_taxonomy = f"{temp_dir}/taxonomy"

            input_scan = f"{temp_dir}/input"
            output_result = f"{temp_dir}/output"

            with open(input_scan, "w") as f:
                f.write(json.dumps({"data": file}))

            save_claravy(knowledge, input_taxonomy, input_alias)

            # Execute the command
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
                    ClaravySvc.AVS_PATH,
                    "-tax",
                    input_taxonomy,
                    "-su",
                    ClaravySvc.SUBSTR_PATH,
                    "-cm",
                    ClaravySvc.MODEL_PATH,
                    "-bl",
                    ClaravySvc.IGNORE_PATH,
                ],
                # capture_output=True,
                text=True,
            )

            if result.stdout:
                self.log.info(f"ClarAVy executed with stdout: {result.stdout}")

            if result.stderr:
                self.log.info(f"ClarAVy executed with stderr: {result.stderr}")

            if result.returncode != 0:
                print(f"ClarAVy returned error code {result.returncode}. No results produced.", file=sys.stderr)
                return None

            return self._parse_claravy_result(output_result)

    def _create_tag_section(self, category: str, tags: Iterator[ClarAVyVerdit]) -> ResultSection:
        """
        Gets a `ResultSection` for a list of tags from a single category.

        Result contains table with AVClass tag information in descending order by rank.

        :param category: Category of tags
        :param tags: Tags belonging to category
        :return: `ResultSection`
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

    def _create_category_sections(self, tags: List[ClarAVyTag]) -> Iterator[ResultSection]:
        """
        Returns a `ResultSection` for each category of AVClass tags.

        :param tags: AVClass tags
        :return: A `ResultSection` for each AVClass tag category
        """
        # Sort tags by category for grouping
        tags = sorted(tags, key=lambda t: CLARAVY_SECTION_ORDER.index(t.category))

        for category, category_tags in groupby(tags, key=lambda t: t.category):
            yield self._create_tag_section(category, category_tags)

    @staticmethod
    def _create_result_section(verdict: ClarAVyVerdit, knowledge: AvKnowledge) -> Optional[ResultSection]:
        """
        Returns a `ResultSection` for AVClass tags.

        :param family: Malware family name extracted by AVClass
        :param is_pup: Whether AVClass detected PUP
        :return: A `ResultSection`
        """

        body = {"is_pup": verdict.is_pup}
        section_tags = dict()

        if verdict.family is not None:
            common_name = verdict.family.lower()

            title = f"ClarAVy identified malware family: {common_name}"
            body["family"] = common_name

            alt_names = knowledge.aliases[tax.FAM].get(common_name, [])

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

        section = ResultSection(
            title,
            json.dumps(body),
            body_format=BODY_FORMAT.KEY_VALUE,
            tags=section_tags,
            heuristic=Heuristic(1) if verdict.family is not None else None,
        )

        return section

    def _get_alt_names(self, family: AnyStr, file_type: AnyStr, use_malpedia: bool) -> List:
        # alt_names is an alphabetically sorted list of translated names and malpedia names
        translation = self.base_data[0]._src_map
        alt_names = [key.lower() for key, value in translation.items() if value == {family}]
        malpedia_names = self.importer.get_alt_names(family, file_type, use_malpedia)
        if malpedia_names:
            alt_names = list(set(alt_names + malpedia_names))
        alt_names.sort()
        return alt_names

    @staticmethod
    def merge_scan_results(a: Dict[Any, str], b: Dict[Any, str]) -> Dict[Any, str]:
        if a:
            r = a.copy()
            r["attributes"]["last_analysis_results"] |= b["attributes"]["last_analysis_results"]
            return r
        else:
            return b

    def execute(self, request: ServiceRequest):
        """Run the service."""
        result = Result()
        request.result = result

        r = reduce(
            ClaravySvc.merge_scan_results,
            [
                i
                for k, items in request.temp_submission_data.items()
                if k in ClaravySvc.VT3_FILE_SOURCE_ATTR
                for i in items
                if i["attributes"]["sha256"].lower() == request.sha256.lower()
            ],
            {},
        )

        if not r:
            self.log.info("No scan detection data found in temp submission data. Skipping.")
            return

        knowledge = self.base_knowledge

        if request.get_param("include_malpedia_dataset"):
            knowledge = self.malpedia_knowledge

        verdict = self._generate_verdict(r, knowledge)

        if not verdict:
            return

        # Build results
        section = ClaravySvc._create_result_section(verdict, knowledge)
        for tag_section in self._create_category_sections(verdict.tags):
            section.add_subsection(tag_section)

        result.add_section(section)
