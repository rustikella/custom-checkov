from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check


class ServiceAccountNotPresent(BaseK8Check):

    def __init__(self):
        # CIS-1.5 5.7.4
        name = "IL service account non va usato"
        # default Service Account and Service/kubernetes are ignored
        id = "CKV_K8S_ALMAVIVA_01"
        supported_kind = ['ServiceAccount']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def scan_spec_conf(self, conf):
        if "metadata" in conf:
            if conf["kind"] == "ServiceAccount" and conf["metadata"]["name"] == "default":
                return CheckResult.FAILED
            if conf["kind"] == "Service" and conf["metadata"]["name"] == "*":
                return CheckResult.FAILED
        return CheckResult.FAILED

check = ServiceAccountNotPresent()
