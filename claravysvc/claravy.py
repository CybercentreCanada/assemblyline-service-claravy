"""This service consumes Anti-Virus tags (`av.virus_name`) and extracts family, behavior, and platform information collected by [ClarAVy](https://github.com/FutureComputing4AI/ClarAVy)."""

from assemblyline.common import forge
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result


class ClaravySvc(ServiceBase):
    """This service consumes Anti-Virus tags (`av.virus_name`) and extracts family, behavior, and platform information collected by [ClarAVy](https://github.com/FutureComputing4AI/ClarAVy)."""

    def execute(self, request: ServiceRequest):
        """Run the service."""

        result = Result()
        request.result = result
