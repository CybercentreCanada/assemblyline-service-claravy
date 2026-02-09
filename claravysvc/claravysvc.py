"""A service which consumes Anti-Virus tags (`av.virus_name`) and extracts family, behaviour and platform.

The service leverages by[ClarAVy](https://github.com/FutureComputing4AI/ClarAVy) to
identify family, behaviour and platform identifiers from Anti-virus tags.
"""

import os
from functools import reduce
from typing import Any, Dict, Set

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result

from .al_reporter import generate_claravy_section
from .claravy_client import ClarAVyError, generate_claravy_verdict
from .corpus import AvKnowledge, consolidate_knowledge, load_claravy, load_malpedia

DATA_PATH = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "data"))


class ClaravySvc(ServiceBase):
    """A service which consumes Anti-Virus tags (`av.virus_name`) and extracts family, behaviour and platform.

    The service leverages by[ClarAVy](https://github.com/FutureComputing4AI/ClarAVy) to
    identify family, behaviour and platform identifiers from Anti-virus tags.
    """

    VT3_FILE_SOURCE_ATTR = ("virus_scan_vt3_files", "virus_total_vt3_files")

    ALIAS_PATH = f"{DATA_PATH}/aliases.txt"
    TAXONOMY_PATH = f"{DATA_PATH}/taxonomy.txt"
    PUP_PATH = f"{DATA_PATH}/pup.txt"

    MAL_FAM_PATH = f"{DATA_PATH}/malpedia-families.json"
    MAL_ACTOR_PATH = f"{DATA_PATH}/malpedia-actors.json"

    def __init__(self, config):
        super().__init__(config)
        self.base_knowledge: AvKnowledge = AvKnowledge({}, {}, set())
        self.malpedia_knowledge: AvKnowledge = AvKnowledge({}, {}, set())
        self.pup_tags: Set[str] = set()

    def start(self) -> None:
        self.base_knowledge = load_claravy(ClaravySvc.TAXONOMY_PATH, ClaravySvc.ALIAS_PATH, ClaravySvc.PUP_PATH)

        # Consolidate the malpedia and base knowledge for scan setting "Use Malpedia"; this will consider
        # malpedia the ground truth if any conflicts arise.
        self.malpedia_knowledge = ClaravySvc.load_malpedia(
            self.base_knowledge, ClaravySvc.MAL_FAM_PATH, ClaravySvc.MAL_ACTOR_PATH
        )

    @staticmethod
    def load_malpedia(auxiliary_knowledge: AvKnowledge, family: str, actor: str) -> AvKnowledge:
        malpedia_knowledge = load_malpedia(family, actor)

        return consolidate_knowledge(malpedia_knowledge, auxiliary_knowledge)

    def _load_rules(self) -> None:
        """Load Malpedia families and actors index.

        This function will check the updates directory and try to load the latest
        Malpedia families and actors index.
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

    @staticmethod
    def merge_scan_results(a: Dict[Any, str], b: Dict[Any, str]) -> Dict[Any, str]:
        """Merge two VT3 File Scan Results together.

        Args:
            a: The first VT3 File Object.
            b: The second VT3 File Object.

        Returns:
            A single VT3 File Object with the scan results including both that of a and b.
        """
        if a:
            r = a.copy()
            r["attributes"]["last_analysis_results"] |= b["attributes"]["last_analysis_results"]
            return r
        else:
            return b

    def execute(self, request: ServiceRequest):
        """Execute the ClarAVy service on the specified request.

        Args:
            request: The request to process.
        """
        result = Result()
        request.result = result

        raw_scan_data = reduce(
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

        if not raw_scan_data:
            self.log.info("No scan detection data found in temp submission data. Skipping.")
            return

        knowledge = self.base_knowledge

        if request.get_param("include_malpedia_dataset"):
            knowledge = self.malpedia_knowledge

        verdict = generate_claravy_verdict(raw_scan_data, knowledge)

        if not verdict:
            return

        try:
            section = generate_claravy_section(knowledge, verdict)
            result.add_section(section)
        except ClarAVyError as e:
            self.log.error(f"Error occured invoking ClarAVy: {e}")
