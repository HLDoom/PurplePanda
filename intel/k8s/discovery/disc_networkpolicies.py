import logging
import json
from kubernetes import client
from typing import List
from intel.k8s.discovery.k8s_disc import K8sDisc
from intel.k8s.models.k8s_model import K8sNamespace, K8sNetworkPolicy


class DiscNetworkPolicies(K8sDisc):
    logger = logging.getLogger(__name__)

    def _disc(self) -> None:
        """
        Discover all the network policies of each namespace
        """

        if not self.reload_api(): return

        namespaces:List[K8sNamespace] = K8sNamespace.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"')
        self._disc_loop(namespaces, self._disc_network_policies, __name__.split(".")[-1])


    def _disc_network_policies(self, ns_obj: K8sNamespace, **kwargs):
        """Discover all the network policies"""

        client_cred = client.NetworkingV1Api(self.cred)
        policies = self.call_k8s_api(f=client_cred.list_namespaced_network_policy, namespace=ns_obj.ns_name)
        if not policies or not policies.items:
            return

        self._disc_loop(policies.items, self._save_network_policy, __name__.split(".")[-1]+f"-{ns_obj.ns_name}", **{"ns_obj": ns_obj})


    def _save_network_policy(self, policy, **kwargs):
        """Given K8s network policy information, save it"""

        ns_obj = kwargs["ns_obj"]
        

        ingressRules = None
        if policy.spec.ingress:
            ingressRules = []
            for rule in policy.spec.ingress:
                ingressRules.append(rule.to_dict())

        egressRules = None
        if policy.spec.egress:
            egressRules = []
            for rule in policy.spec.egress:
                egressRules.append(rule.to_dict())

        # Create network policy object
        netpol_obj = K8sNetworkPolicy(
            name = f"{ns_obj.ns_name}:{policy.metadata.name}",
            uid = policy.metadata.uid,
            labels = json.dumps(policy.metadata.labels),
            annotations = json.dumps(policy.metadata.annotations),
            policy_types = policy.spec.policy_types,
            pod_selector = json.dumps(policy.spec.pod_selector.to_dict()),
            ingress_rules = json.dumps(ingressRules),
            egress_rules = json.dumps(egressRules)
        ).save()

        netpol_obj.namespaces.update(ns_obj)
        netpol_obj.save()
        # Pod relations have to be added after disc phase has finished
