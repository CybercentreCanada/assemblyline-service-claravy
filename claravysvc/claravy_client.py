"""A client for the ClarAVy Python Module which manages aggregating VT3 File scan results."""

import functools
import itertools
import json
import math
import multiprocessing
import os
import pickle
import random
import re
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List, NamedTuple, Optional, Set

import claravy.taxonomy as tax
import numpy as np
from claravy.avalias import AVAlias
from claravy.avparse import AVParse
from claravy.avstats import AVStats
from claravy.avtagger import get_batch_stats, line_batcher, process_batch
from claravy.ibcc.IBCC import IBCC
from UltraDict import UltraDict

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

_confidence_model = None


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

        claravy_inference(
            [input_scan],
            output_result,
            input_alias,
            AVS_PATH,
            input_taxonomy,
            SUBSTR_PATH,
            IGNORE_PATH,
        )

        return _parse_claravy_result(knowledge.pup_tags, output_result)


def initialize_claravy():
    global _confidence_model

    if _confidence_model:
        return

    with open(MODEL_PATH, "rb") as f:
        _confidence_model = pickle.load(f)

    # Force warm-up of model so we don't pay the penalty when we actually need the service
    X = np.zeros((5, 7), dtype=np.float64)
    _confidence_model.predict_proba(X)

    num_annotators = 5
    num_labels = 5
    W = np.ones(num_annotators, dtype=np.float64)
    C = np.full((1, num_annotators), -1, dtype=np.int32)
    C[0, 0] = 0

    warm_up_ibcc = IBCC(
        L=num_labels,
        K=num_annotators,
        W=W,
        max_iter=2,
        n_jobs=1,
        verbose=False
    )
    warm_up_ibcc.fit_predict(C)


def claravy_inference(
    scan_files,
    out_file,
    alias_file,
    av_file,
    tax_file,
    substr_file,
    ignore_file,
    *,
    beh_threshold=5,
    file_threshold=5,
    vuln_threshold=1,
    pack_threshold=1,
    grp_threshold=1,
    hash_format="md5",
    batch_size=1000,
    num_processes=1,
):
    # Create AV parser
    vote_thresholds = {
        tax.GRP: grp_threshold,
        tax.CAT: beh_threshold,
        tax.FILE: file_threshold,
        tax.VULN: vuln_threshold,
        tax.PACK: pack_threshold,
    }

    # Object for parsing AV scan data
    av_parser = AVParse(av_file, ignore_file, vote_thresholds, hash_format)
    token_vocab = av_parser.read_vocab(tax_file)

    # Parse AV scan reports in batches
    batcher = line_batcher(scan_files, None, batch_size)
    map_func = functools.partial(get_batch_stats, av_parser=av_parser, token_vocab=token_vocab)

    # Compute stats about AV labels in scan reports
    # Uses ProcessPoolExecutor to process batches of AV scans in parallel
    av_stats = AVStats(av_parser.supported_avs)
    mp_context = multiprocessing.get_context("spawn")
    input_left = True
    total_batches = 0
    N = 0  # Number of scan reports
    while input_left:
        batches = itertools.islice(batcher, num_processes)
        with ProcessPoolExecutor(max_workers=num_processes, mp_context=mp_context) as batch_exec:
            results = batch_exec.map(map_func, batches)
        num_batches = 0
        for av_stats_mapper in results:
            av_stats.reduce_stats(av_stats_mapper)
            num_batches += 1
            N += av_stats_mapper.num_scans
        if num_batches < num_processes:
            input_left = False
        total_batches += num_batches
        if num_batches > 0:
            msg = "Computed stats for {} total batches of scan reports"

    # Finalize token vocab and token stats
    token_vocab, alias_mapping = av_parser.read_aliases(alias_file, token_vocab)
    token_vocab, _ = av_parser.update_vocab(av_stats, token_vocab)
    av_stats.update_token_stats(token_vocab, alias_mapping, av_parser.correlated_avs, av_parser.new_fam_tokens)
    av_parser.update_av_heur_labels(av_stats.av_heur_labels)

    # Resolve aliases using the stats computed about tokens in AV labels
    av_alias = AVAlias(av_stats, token_vocab, av_parser, alias_mapping, substr_file)
    alias_mapping = av_alias.alias_mapping
    token_vocab = av_alias.token_vocab

    # Defensive clean-up of UltraDict to prevent namespace clash (i.e. if a previous run failed)
    UltraDict.unlink_by_name("shm_token_vocab", ignore_errors=True)
    UltraDict.unlink_by_name("shm_token_vocab_memory", ignore_errors=True)
    UltraDict.unlink_by_name("shm_alias_mapping", ignore_errors=True)
    UltraDict.unlink_by_name("shm_alias_mapping_memory", ignore_errors=True)

    # Use UltraDict to support sharing token_vocab between processes.
    # Treated as read-only from this point on.
    token_dump_size = sys.getsizeof(token_vocab) + 1000
    alias_dump_size = sys.getsizeof(alias_mapping) + 1000

    # Even though we do not use this reference we need to hold onto it to prevent from being GCd.
    # ClarAVy references these later via the string name.
    _shm_alias_mapping = UltraDict(
        alias_mapping, name="shm_alias_mapping", buffer_size=alias_dump_size, create=True, shared_lock=True
    )

    _shm_token_vocab = UltraDict(
        token_vocab, name="shm_token_vocab", buffer_size=token_dump_size, create=True, shared_lock=True
    )

    # Use UltraDict to support sharing alias_mapping memory between processes.
    # Treated as read-only from this point on.

    # Function for getting tag ranking and family votes for each AV scan
    batcher = line_batcher(scan_files, None, batch_size)
    map_func = functools.partial(process_batch, av_parser=av_parser)

    # Map each AV product to a unique ID and vice-versa
    # Map each family to a unique ID and vice-versa
    idx_avs = sorted(av_stats.supported_avs)
    av_idxs = {av: idx for idx, av in enumerate(idx_avs)}
    idx_fams = []
    fam_idxs = {}
    L = 0
    K = len(av_idxs)

    # Output tagging results and track family annotations
    C = np.zeros((N, K), dtype=np.int32) - 1
    X = np.zeros((N, 7), dtype=np.float64)
    W = np.array(av_parser.av_weights, dtype=np.float64)
    confidence_scores = np.zeros(N, dtype=np.float64)
    hashes = []
    ratios = []
    tags = []
    input_left = True
    total_batches = 0

    i = 0
    while input_left:
        batches = itertools.islice(batcher, num_processes)
        with ProcessPoolExecutor(max_workers=num_processes, mp_context=mp_context) as batch_exec:
            results = batch_exec.map(map_func, batches)

        num_batches = 0
        for b_hashes, b_tags, b_families, b_features, b_detects in results:
            hashes += b_hashes
            tags += b_tags
            ratios += b_detects
            for file_hash, fams, features in zip(b_hashes, b_families, b_features):
                # Assign IDs to new families
                fam_list = fams.keys()
                for family in fam_list:
                    if fam_idxs.get(family) is None:
                        idx_fams.append(family)
                        fam_idxs[family] = L
                        L += 1

                # Sample from correlated AVs that vote for the same family
                for family, avs in fams.items():
                    fam_idx = fam_idxs[family]
                    skip_avs = set()
                    avs = list(avs)
                    random.shuffle(avs)
                    for cur_av in avs:
                        if cur_av in skip_avs:
                            continue
                        corr_avs = av_parser.correlated_avs[cur_av]
                        corr_avs.add(cur_av)
                        skip_avs.update(corr_avs)
                        av_idx = av_idxs[cur_av]
                        C[i, av_idx] = fam_idx

                X[i, :] = features
                i += 1

            # Finished the current batch
            num_batches += 1

        # Check if we have processed all batches
        if num_batches < num_processes:
            input_left = False
        total_batches += num_batches

    # Track idxs of families that were auto-identified
    new_fam_idxs = set()
    for fam in av_parser.new_fam_tokens:
        if fam_idxs.get(fam) is None:
            continue
        fam_idx = fam_idxs[fam]
        new_fam_idxs.add(fam_idx)

    # Identify families that are almost never the plurality
    plur_fams = []
    plur_counts = []
    fam_plur = {fam_idx: 0 for fam_idx in new_fam_idxs}
    fam_total = {fam_idx: 0 for fam_idx in new_fam_idxs}
    for i in range(N):
        scan = C[i]
        labels, counts = np.unique(scan[scan != -1], return_counts=True)
        if not len(counts):
            plur_fams.append(-1)
            plur_counts.append(0)
            continue

        # If there are ties, choose plurality randomly
        shuffled_idxs = list(range(len(labels)))
        random.shuffle(shuffled_idxs)
        labels = labels[shuffled_idxs]
        counts = counts[shuffled_idxs]

        max_count = max(counts)
        plur_fam = -1
        for label, count in zip(labels, counts):
            if fam_plur.get(label) is None:
                fam_plur[label] = 0
                fam_total[label] = 0
            if count == max_count:
                plur_fam = label
                fam_plur[label] += 1
            fam_total[label] += 1
        plur_fams.append(plur_fam)
        plur_counts.append(max_count)

    # Remove annotations with those families
    for fam_idx in new_fam_idxs:
        total = fam_total[fam_idx]
        plur = fam_plur[fam_idx]

        # Criteria for removal: plurality less than 10% of the time
        if total >= 1 and plur / total <= 0.1:
            C[C == fam_idx] = -1

    ibcc_model = IBCC(
        L=L + 1,
        K=K,
        W=W,
        max_iter=1,
        eps=0.01,
        beta0_factor=N / 100,
        n_jobs=num_processes,
        verbose=True,
    )

    posterior, _, _ = ibcc_model.fit_predict(C)

    # Update features with posterior
    for scan_idx in range(len(hashes)):
        most_likely_prob = 0.0
        pred_entropy = 0.0
        for _, prob in posterior[scan_idx]:
            if prob > most_likely_prob:
                most_likely_prob = prob
            if prob == 0:
                continue
            log_prob = math.log(prob)
            pred_entropy -= prob * log_prob
        X[scan_idx, 5] = most_likely_prob
        X[scan_idx, 6] = pred_entropy

    # Get confidence scores
    confidence_scores = _confidence_model.predict_proba(X)

    # Write SparseIBCC output
    with open(out_file, "w") as f:
        for scan_idx, file_hash in enumerate(hashes):
            scan_posterior = posterior[scan_idx]
            tag_str = tags[scan_idx]
            detect_ratio = ratios[scan_idx]
            most_likely_fam = -1
            most_likely_prob = 0.0
            for fam, prob in scan_posterior:
                if prob > most_likely_prob:
                    most_likely_fam = fam
                    most_likely_prob = prob
            if most_likely_fam == -1:
                family = "SINGLETON:{}".format(file_hash)
                confidence = 0.0
            else:
                family = idx_fams[most_likely_fam]
                confidence = float(confidence_scores[scan_idx, 1]) * 100
            fam_str = "FAM:{}|{:.2f}%".format(family, confidence)
            msg = "{}\t{}\t{}".format(file_hash, detect_ratio, fam_str)
            if len(tag_str):
                msg += ",{}".format(tag_str)
            f.write(msg + "\n")
