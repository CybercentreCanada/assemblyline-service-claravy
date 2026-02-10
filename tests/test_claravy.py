import json
import os
import shutil

import io
import gzip
import base64

from pathlib import Path

import pytest
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

from claravysvc.claravysvc import ClaravySvc

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

TEST_DATA = f"{TEST_DIR}/test_claravy"


def _zip_text(text_input: str) -> str:
    buf = io.BytesIO()

    with gzip.GzipFile(fileobj=buf, mode='wb', compresslevel=9) as f:
        f.write(text_input.encode('utf-8'))

    compressed_bytes = buf.getvalue()
    base64_encoded = base64.b64encode(compressed_bytes).decode('utf-8')

    return base64_encoded

def package_scan_report(vt3_results):
    return _zip_text(
            json.dumps([
                f
                for f in vt3_results
            ]
        )
    )


def create_test_sample(md5, sha1, sha256):
    return dict(
        sid=1,
        metadata={},
        service_name="antivirus",
        service_config={},
        fileinfo=dict(
            magic="ASCII text, with no line terminators",
            md5=md5,
            mime="text/plain",
            sha1=sha1,
            sha256=sha256,
            size=19,
            type="unknown",
        ),
        filename="dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8",
        min_classification="TLP:WHITE",
        max_files=501,
        ttl=3600,
        safelist_config={"enabled": False, "hash_types": ["sha1", "sha256"], "enforce_safelist_service": False},
    )


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def claravy_service():
    create_tmp_manifest()
    try:
        yield ClaravySvc({})
    finally:
        remove_tmp_manifest()


def load_test_data():
    all_scenarios = []
    all_names = []
    for path in Path(TEST_DATA).iterdir():
        if not path.is_file():
            continue

        with open(path) as f:
            file_data = json.load(f)

        for i, scenario in enumerate(file_data):
            all_scenarios.append(scenario)

            all_names.append(f"{path.stem}-index-{i}")

    return {"argvalues": all_scenarios, "ids": all_names}


@pytest.mark.parametrize("scenario", **load_test_data())
def test_execute_temp_submission_data(scenario, claravy_service):
    sample = create_test_sample(scenario["input"]["md5"], scenario["input"]["sha1"], scenario["input"]["sha256"])

    claravy_service.start()

    service_task = ServiceTask(sample)
    service_task.service_config = {"include_malpedia_dataset": True}

    task = Task(service_task)
    task.get_param
    service_request = ServiceRequest(task)
    service_request.temp_submission_data = {
        "virus_total_vt3_files": package_scan_report(
            scenario["input"]["temp_submission_data"]["virus_total_vt3_files"]
        ),
        "virus_scan_vt3_files": package_scan_report(
            scenario["input"]["temp_submission_data"]["virus_scan_vt3_files"]
        )
    }

    claravy_service.execute(service_request)

    assert len(service_request.result.sections) == 1

    result = service_request.result.sections[0]

    if scenario["output"]["tags"]:
        assert len(result.subsections) == 1
        subsection = result.subsections[0]

        paths = set(x["path"] for x in json.loads(subsection.body))

        assert set(scenario["output"]["tags"]) == paths
    else:
        assert len(result.subsections) == 0

    assert set(result.tags["attribution.family"]) == set(scenario["output"]["family"])

    if scenario["output"]["actors"]:
        assert set(result.tags["attribution.actor"]) == set(scenario["output"]["actors"])

    body = json.loads(result.body)

    assert body["is_pup"] == scenario["output"]["is_pup"]

    if scenario["output"]["aka"]:
        assert set(x.strip() for x in body["aka"].split(",")) == set(scenario["output"]["aka"])
