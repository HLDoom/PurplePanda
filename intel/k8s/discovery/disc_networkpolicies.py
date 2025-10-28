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
        """
        Discover all the network policies
        """

        client_cred = client.NetworkingV1Api(self.cred)
        policies = self.call_k8s_api(f=client_cred.list_namespaced_network_policy, namespace=ns_obj.ns_name)
        if not policies or not policies.items:
            return

        self._disc_loop(policies.items, self._save_network_policy, __name__.split(".")[-1]+f"-{ns_obj.ns_name}", **{"ns_obj": ns_obj})


    def _save_network_policy(self, policy, **kwargs):
        """Given K8s network policy information, save it"""

        ns_obj = kwargs["ns_obj"]
        ns_name = ns_obj.name

        # Process pod selector
        # TODO: matchExpression
        pod_selector = {}
        if policy.spec.pod_selector and policy.spec.pod_selector.match_labels:
            pod_selector = policy.spec.pod_selector.match_labels

        # Process ingress rules
        ingress_rules = []
        if policy.spec.ingress:
            for rule in policy.spec.ingress:
                rule_data = {
                    "ports": [],
                    "from": []
                }

                # Process ports
                if rule.ports:
                    for curPort in rule.ports:
                        curPort_data = {
                            "protocol": curPort.protocol if curPort.protocol else "TCP", # I think k8s always fills/defaults to TCP, but better to set manually
                            "port": str(curPort.port) if curPort.port else None, # Note: behaviour for undefined != empty
                            "end_port": curPort.end_port if hasattr(curPort, "end_port") else None # Same here
                        }
                        rule_data["ports"].append(curPort_data)

                # Process from (sources)
                if rule._from:
                    for source in rule._from:
                        source_data = {}

                        if source.pod_selector:
                            source_data["podSelector"] = {
                                "matchLabels": source.pod_selector.match_labels if source.pod_selector.match_labels else None,
                                "matchExpressions": self._process_match_expressions(source.pod_selector.match_expressions) if source.pod_selector.match_expressions else None
                            }

                        if source.namespace_selector:
                            source_data["namespaceSelector"] = {
                                "matchLabels": source.namespace_selector.match_labels if source.namespace_selector.match_labels else None,
                                "matchExpressions": self._process_match_expressions(source.namespace_selector.match_expressions) if source.namespace_selector.match_expressions else None
                            }

                        if source.ip_block:
                            source_data["ipBlock"] = {
                                "cidr": source.ip_block.cidr,
                                "except": source.ip_block._except if source.ip_block._except else []
                            }

                        rule_data["from"].append(source_data)

                ingress_rules.append(rule_data)

        # Process egress rules
        egress_rules = []
        if policy.spec.egress:
            for rule in policy.spec.egress:
                rule_data = {
                    "ports": [],
                    "to": []
                }

                # Process ports
                if rule.ports:
                    for curPort in rule.ports:
                        curPort_data = {
                            "protocol": curPort.protocol if curPort.protocol else "TCP",
                            "port": str(curPort.port) if curPort.port else None,
                            "end_port": curPort.end_port if hasattr(curPort, "end_port") else None
                        }
                        rule_data["ports"].append(curPort_data)

                # Process to (destinations)
                if rule.to:
                    for dest in rule.to:
                        dest_data = {}

                        if dest.pod_selector:
                            dest_data["podSelector"] = {
                                "matchLabels": dest.pod_selector.match_labels if dest.pod_selector.match_labels else None,
                                "matchExpressions": self._process_match_expressions(dest.pod_selector.match_expressions) if dest.pod_selector.match_expressions else None
                            }

                        if dest.namespace_selector:
                            dest_data["namespaceSelector"] = {
                                "matchLabels": dest.namespace_selector.match_labels if dest.namespace_selector.match_labels else None,
                                "matchExpressions": self._process_match_expressions(dest.namespace_selector.match_expressions) if dest.namespace_selector.match_expressions else None
                            }

                        if dest.ip_block:
                            dest_data["ipBlock"] = {
                                "cidr": dest.ip_block.cidr,
                                "except": dest.ip_block._except if dest.ip_block._except else []
                            }

                        rule_data["to"].append(dest_data)

                egress_rules.append(rule_data)

        policy_types = policy.spec.policy_types if policy.spec.policy_types else []

        # Create network policy object
        netpol_obj = K8sNetworkPolicy(
            name = f"{ns_name}:{policy.metadata.name}",
            uid = policy.metadata.uid,
            labels = json.dumps(policy.metadata.labels),
            annotations = json.dumps(policy.metadata.annotations),
            policy_types = policy_types,
            pod_selector = json.dumps(pod_selector),
            ingress_rules = json.dumps(ingress_rules),
            egress_rules = json.dumps(egress_rules)
        ).save()

        netpol_obj.namespaces.update(ns_obj)
        netpol_obj.save()

    def _process_match_expressions(self, match_expressions):
        """Split matchExpressions into map (I thought operator was optional, but apparently not)"""
        if not match_expressions:
            return None

        result = []
        for expr in match_expressions:
            result.append({
                "key": expr.key,
                "operator": expr.operator,
                "values": expr.values if expr.values else None # I think None is correct for this?
            })
        return result
