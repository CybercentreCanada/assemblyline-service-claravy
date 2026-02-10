import gzip
import base64
import json
import io
from typing import Optional

def unpackage_report(b64_string: Optional[str]):
    if not b64_string:
        return []

    try:
        compressed_bytes = base64.b64decode(b64_string)

        buf = io.BytesIO(compressed_bytes)
        with gzip.GzipFile(fileobj=buf, mode='rb') as f:
            decompressed_text = f.read().decode('utf-8')

        return json.loads(decompressed_text)
    except Exception as e:
        return []
