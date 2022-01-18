from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class AddExists(BaseDockerfileCheck):
    def __init__(self):
        name = "Ensure that mvn is not used in Dockerfiles"
        id = "CKV_DOCKER_ALMAVIA_1"
        #supported_instructions = ["ADD"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_instructions=supported_instructions)

    def scan_entity_conf(self, conf):
        for instruction in conf:
            if instruction['instruction'] == "mvn":
                return CheckResult.FAILED, conf[0]
        return CheckResult.PASSED,None


check = AddExists()