import logging
import yaml
import os
import json

from intel.k8s.models.k8s_model import *
from .k8s_disc import K8sDisc
from core.db.customogm import graph
from kubernetes import client

class AnalyzeResults(K8sDisc):
    logger = logging.getLogger(__name__)
    already_privesc = set()

    def _disc(self) -> None:
        """
        Process the found information to be able to find privilege escalation paths easily in the database.
        """

        # Analyze network policies and create CAN_CONNECT relationships
        self._analyze_network_policies()

        with open(os.path.dirname(__file__) + "/../info/privesc.yaml", "r") as stream:
            self.analysis_data = yaml.safe_load(stream)

        privesc_techs = self.analysis_data["privesc"]

        # Create known groups relations
        self._create_known_groups_relations()

        # Set escape to node
        self._potential_escape_to_node()

        # Create GSAs run in pods
        self._gcp_sas_running_in_pod()

        # Get privescs
        self._disc_loop(privesc_techs, self._check_privesc_tech, __name__.split(".")[-1])
    

    def _check_privesc_tech(self, privesc_tech):
        """Check each privesc check"""

        title = privesc_tech["title"]
        summary = privesc_tech["summary"]
        limitations = privesc_tech.get("limitations", "")
        relation = privesc_tech["relation"]
        self.logger.info(f"Checking privesc: {title}")
        for ppal_obj in K8sUser.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"') + K8sGroup.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"') + K8sServiceAccount.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"'):
            
            objs_to_privesc = self._get_ppal_privesc(privesc_tech, ppal_obj)
            
            for _, obj_to_privesc in objs_to_privesc.items():
                to_privesc_ppal_obj = obj_to_privesc["ppal_obj"].save()
                reason = obj_to_privesc["reason"]

                # Update interesting permission
                self._update_interesting_permissions(ppal_obj, reason)
                
                # If not a ppal we don't want to escalate privs to it
                if "K8s" in to_privesc_ppal_obj.__node__._labels and "K8sPrincipal" not in to_privesc_ppal_obj.__node__._labels:
                    continue
                
                # Do not privesc to yourself
                if ppal_obj.__primaryvalue__ == to_privesc_ppal_obj.__primaryvalue__ and\
                    type(ppal_obj) == type(to_privesc_ppal_obj):
                    continue
                
                if obj_to_privesc["escape_to_node"] and not ppal_obj.potential_escape_to_node:
                    ppal_obj.potential_escape_to_node = True
                    ppal_obj.save()
                
                if relation.upper() == "PRIVESC":
                    privesc_rel_name = f"{ppal_obj.__primaryvalue__}->{to_privesc_ppal_obj.__primaryvalue__}"
                    if not privesc_rel_name in self.already_privesc:
                        ppal_obj = ppal_obj.privesc_to(to_privesc_ppal_obj, reasons=[reason], title=title, summary=summary, limitations=limitations)
                        self.already_privesc.add(privesc_rel_name)
                
                else:
                    self.logger.error(f"Uknown relation {relation}")


    def _create_known_groups_relations(self):
        """
        There are some important default groups we need to consider
        """

        # All users are member of system:authenticated
        query = '''MERGE (auth_group:K8s:K8sPrincipal:K8sGroup{name:"'''+self.cluster_id+'''-system:authenticated"})
                WITH auth_group
                MATCH (users:K8sUser) WHERE users.name =~ "'''+self.cluster_id+'''-.*"
                MERGE (users)-[:MEMBER_OF]->(auth_group)
                WITH auth_group
                MATCH (groups:K8sGroup) WHERE groups.name <> "'''+self.cluster_id+'''-system:authenticated" AND groups.name =~ "'''+self.cluster_id+'''-.*"
                MERGE (groups)-[:MEMBER_OF]->(auth_group)
                return auth_group'''

        graph.evaluate(query)

        # All service accounts are inside "system:serviceaccounts"
        query = '''MERGE (group:K8s:K8sPrincipal:K8sGroup{name:"'''+self.cluster_id+'''-system:serviceaccounts"})
                WITH group
                MATCH (sas:K8sServiceAccount) WHERE sas.name =~ "'''+self.cluster_id+'''-.*"
                MERGE (sas)-[:MEMBER_OF]->(group)
                return group'''

        graph.evaluate(query)


        query = '''MATCH (ns:K8sNamespace)<-[:PART_OF]-(sa:K8sServiceAccount) WHERE ns.name =~ "'''+self.cluster_id+'''-.*"
                MERGE (group:K8s:K8sPrincipal:K8sGroup{name:"'''+self.cluster_id+'''-system:serviceaccounts:"+ns.ns_name})
                MERGE (group)<-[:MEMBER_OF]-(sa)
                RETURN group'''

        graph.evaluate(query)
    

    def _potential_escape_to_node(self):

        query = """MATCH(p:K8sPod)
            WHERE p.host_network OR
            p.host_pid OR
            any(path IN p.host_path WHERE any( regex IN ["/", "/proc.*", "/sys.*", "/dev.*", "/var", "/var/", "/var/log.*", "/var/run.*", ".*docker.sock", ".*crio.sock", ".*/kubelet.*", ".*/pki.*", "/home/admin.*", "/etc.*", ".*/kubernetes.*", ".*/manifests.*", "/root.*"] WHERE regex =~ replace(path, "\\\\", "\\\\\\\\") ))
            SET p.potential_escape_to_node = true
            RETURN p"""
        
        graph.evaluate(query)

        query = """MATCH(c:K8sContainer)
            WHERE c.sc_privileged = True OR
            size(c.sc_capabilities_add) > 0
            SET c.potential_escape_to_node = true
            RETURN c"""
        
        graph.evaluate(query)
    
    def _gcp_sas_running_in_pod(self):
        """If the GCP cluster has a SA, it's accessible from the pods"""

        query = """MATCH(p:K8sPod)-[:PART_OF]->(ns:K8sNamespace)-[:PART_OF]->(:GcpCluster)<-[r:RUN_IN]-(sa:GcpServiceAccount)
            MERGE (p)<-[:RUN_IN {scopes: r.scopes}]-(sa)
            RETURN p
            """
        
        graph.evaluate(query)
    

    def _update_interesting_permissions(self, ppal:K8sPrincipal, reason: str):
        """Given a principal and the interesting permissions discovered, update it"""
        
        if not ppal.interesting_permissions:
            ppal.interesting_permissions = [reason]
            ppal = ppal.save()
        elif not reason in ppal.interesting_permissions:
            ppal.interesting_permissions.append(reason)
            ppal = ppal.save()


    def _get_ppal_privesc(self, privesc_tech:dict, ppal_obj: K8sPrincipal) -> dict:
        """
        Given a privesc technique and a principal object, check if the principal can use it to escalate
        """

        verbs = privesc_tech["verbs"]
        resources = privesc_tech["resources"]
        resource_names_req = privesc_tech.get("resource_names", [])
        privesc_to = privesc_tech.get("privesc_to", "")
        privesc_to_cloud = privesc_tech.get("privesc_to_cloud", False)
        class_name = privesc_tech.get("class_name", "")
        assert privesc_to or class_name, "There is a privesc tecnique without privesc_to and class_name"

        privescs_to_node_resources = self.analysis_data["extra_info"]["privescs_to_node_resources"]
        
        privect_to_objs = {}
        for res_obj, rel in ppal_obj.resources._related_objects:
            rel_verbs = rel["verbs"]
            apiGroups = rel["api_groups"]
            role_name = rel["role_name"]
            bind_name = rel["bind_name"]
            resource_names = rel["resource_names"]

            # Resource name can be like "pods" or "namespace_name:pods", so we get the "-1" splitting by ":"
            affected_resource_name = res_obj.name.split(":")[-1].lower()
            
            # Check if the resource is affected
            if not affected_resource_name == "*" and not any(res in affected_resource_name for res in resources): # The any is used so "pods" inside "pods/log" gives true (check TODO in privesc.yaml)
                continue

            # Check the ppal has all the required verbs permissions
            if not "*" in rel_verbs and not all(v in rel_verbs for v in verbs):
                continue

            if resource_names and resource_names_req:
                # Check if the resource name is affected
                if not any(res_name_req.lower() in res_name.lower() for res_name in resource_names for res_name_req in resource_names_req):
                    continue
            
            for _, ppal_obj in self._get_privesc_to_objs(privesc_to, privesc_to_cloud, class_name, res_obj.name).items():

                privect_to_objs[ppal_obj["ppal_obj"].__primaryvalue__] = {
                    "ppal_obj": ppal_obj["ppal_obj"],
                    "reason": f"The {'ClusterRole' if res_obj.name == affected_resource_name else 'Role'} '{role_name}' assigned by the binding '{bind_name}' fulfill the necessary privesc permissions '{', '.join(verbs)}' with the set of permissions '{', '.join(rel_verbs)}' over the resource '{res_obj.name}'. {ppal_obj['extra_reason']}",
                    "escape_to_node": res_obj.name in privescs_to_node_resources
                }
        
        return privect_to_objs
            
    
    def _get_privesc_to_objs(self, privesc_to: str, privesc_to_cloud: bool, class_name: str, res_name: str):
        """
        Given a privesc_to info, get all the affected objects the ppal can escalate to
        """
        
        privect_to_objs = {}
        ns_name = res_name.split(":")[0]
        
        # Relate to all SAs in the namespace (if ClusterRole, in all)
        if privesc_to == "Namespace SAs":
            if len(res_name.split(":")) == 1:
                # Privesc to all the clusters SAs
                for sa_obj in K8sServiceAccount.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"'):
                    privect_to_objs[sa_obj.__primaryvalue__] = {"ppal_obj": sa_obj, "extra_reason": ""}
                
                # Privesc to all the GSA of the cluster
                if privesc_to_cloud:
                    for pod_obj in K8sPod.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"'):
                        self.escalate_to_cloud_ppals(privect_to_objs, pod_obj, privesc_to_cloud)
            
            else:
                ns_obj = K8sNamespace(name=ns_name).save()
                for sa_obj, rel in ns_obj.serviceaccounts._related_objects:
                    # Coger todos los GSA en el namespace y escalar a ellos
                    if type(sa_obj) is not K8sServiceAccount:
                        self.logger.error(f"Type {type(sa_obj)} with name {sa_obj.__primaryvalue__} found as service account in namespace {ns_name.name} for privesc")
                    else:
                        privect_to_objs[sa_obj.__primaryvalue__] = {"ppal_obj": sa_obj, "extra_reason": ""}
                
                # Privesc to all the GSA running in the pods of the cluster
                if privesc_to_cloud:
                    for pod_obj, _ in ns_obj.pods._related_objects:
                        self.escalate_to_cloud_ppals(privect_to_objs, pod_obj, privesc_to_cloud)
        
        # Relate to the SA running in the resource inside a namespace (if ClusterRole, in all) and to all the SAs whose secret token can be accesed by the item
        elif privesc_to == "Running SA":
            assert class_name, "class_name needs to be specified with 'Running SA' privesc_to"
            K8sKlass = globals()[class_name]
            
            for item in K8sKlass.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"'):
                # If namespace dependant and object not related with the namespace, continue
                if ns_name and not any(ns_obj.name.lower() == ns_name.lower() for ns_obj, _ in item.namespaces._related_objects):
                    continue
                
                for sa_obj, _ in item.serviceaccounts._related_objects:
                    if type(sa_obj) is not K8sServiceAccount:
                        self.logger.error(f"Type {type(sa_obj)} with name {sa_obj.__primaryvalue__} found as service account from item {item.__primaryvalue__} for privesc")
                    else:
                        privect_to_objs[sa_obj.__primaryvalue__] = {"ppal_obj": sa_obj, "extra_reason": ""}

                # Privesc to the running GSA inside the object (if any)
                self.escalate_to_cloud_ppals(privect_to_objs, item, privesc_to_cloud)
                
                # The object might be also related to secrets (like a pod having them mounted) that can be also stealed
                if  hasattr(item, "secrets"):
                    for secret, _ in item.secrets._related_objects:
                        for sa_obj, _ in secret.serviceaccounts._related_objects:
                            if type(sa_obj) is not K8sServiceAccount:
                                self.logger.error(f"Type {type(sa_obj)} with name {sa_obj.__primaryvalue__} found as service account from secret {secret.name} for privesc")
                            else:
                                privect_to_objs[sa_obj.__primaryvalue__] = {"ppal_obj": sa_obj, "extra_reason": f"Note that he SA secret can be accessed by {item.__primaryvalue__}."}

        # Relate to the class objects inside a namespace (if ClusterRole, in all)
        # To the cloud, from K8s via "RUN_IN" relations we can only escape from Pods. As a Pod isn a Principal in K8s
        ## you won't be able to escape to the cloud using the techniques that specifies the K8s Pricipal to escape to
        elif not privesc_to and class_name:
            K8sKlass = globals()[class_name]
            # ClusterRole or Global ppal (User or Group)
            if not ns_name or not hasattr(K8sKlass, "namespaces"):
                for obj in K8sKlass.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"'):
                    privect_to_objs[obj.__primaryvalue__] = {"ppal_obj": obj, "extra_reason": ""}
            
            else:
                # Has namespace, so look for the SAs of that namespace
                for item in K8sKlass.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"'):
                    if not any(ns_obj.name.lower() == ns_name.lower() for ns_obj, _ in item.namespaces._related_objects):
                        continue
                    
                    for sa_obj, _ in item.serviceaccounts._related_objects:
                        privect_to_objs[sa_obj.__primaryvalue__] = {"ppal_obj": sa_obj, "extra_reason": ""}
        
        # Relate to all the privescs in the namespace (if ClusterRole, in all)
        # APPARENTLY THIS TEHCNIQUE IS NO LONGER WORKING SO IT'S NOT NEEDED
        #elif privesc_to == "roles":
        #    ppals_obj = K8sPrincipal.get_all_with_relation("PRIVESC", get_only_end=True)
            # TODO: Indicate in the extra_reson which role/rolebind to patch to escalate priileges.
            # extra_reason = "This is possible abusing the "
        #    for ppal_obj in ppals_obj:
        #        if not ns_name or not hasattr(ppal_obj, "namespaces"):
        #            privect_to_objs[ppal_obj.__primaryvalue__] = {"ppal_obj": ppal_obj, "extra_reason": ""}
        #        
        #        else:
        #            if any(ns_obj.name.lower() == ns_name.lower() for ns_obj, _ in ppal_obj.namespaces._related_objects):
        #                privect_to_objs[ppal_obj.__primaryvalue__] = {"ppal_obj": ppal_obj, "extra_reason": ""}
        
        else:
            self.logger.error(f"Unknown combination of privesc_to ({privesc_to}) and class_name ({class_name})")

        return privect_to_objs
    

    def escalate_to_cloud_ppals(self, privect_to_objs, k8s_obj, privesc_to_cloud):
        """
        Given the dict of ppals to escalate to, the object where GSAs might be running and the bool
        indicating if an escalation is needed. Decide if it's possible to escalate.
        """
        # Privesc to the running GSA inside the object (if any)
        if privesc_to_cloud and hasattr(k8s_obj, "running_gcp_service_accounts"):
            for gcp_sa_obj, _ in k8s_obj.running_gcp_service_accounts._related_objects:
                if gcp_sa_obj.__primaryvalue__ is not None: #For some reason py2neo sometimes duplicates the GSA, but one of them has None in email
                    privect_to_objs[gcp_sa_obj.__primaryvalue__] = {"ppal_obj": gcp_sa_obj, "extra_reason": f"SA running in {k8s_obj.name}"}


    def _analyze_network_policies(self):
        """
        Analyze network policies and create CAN_CONNECT relationships between pods.

        Kubernetes network policy logic (oh no..):
        - Default: allow all
        - NetworkPolicy selects a pod and has a policyTypes = pod is isolated
        - Multiple policies are additive, allowed connections = UNION of all applicable policies
        - Empty {} from/to in a rule = allow all for that rule
        - For a connection to succeed: BOTH egress from source AND ingress to destination must allow it

        Cross-namespace behavior in rules (from/to fields):
        - podSelector & nsSelector = empty/None: selects all pods in scope
        - podSelector alone (no namespaceSelector): selects pods in the policy's own namespace only by labels
        - namespaceSelector alone (no podSelector): selects all pods in matching namespace(s)
        - both: selects specific pods in matching namespace(s)
        
        PS: I think this is not doable in pure queries
        """

        self.logger.info("Analyzing network policies for pod connectivity across entire cluster")

        # Get pods from all namespaces
        self.all_pods: list[client.V1Pod] = K8sPod.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"')
        
        if not self.all_pods:
            self.logger.debug("No pods found in cluster?")
            return

        # Get network policies from all namespaces
        self.all_netPols: list[client.V1NetworkPolicy] = K8sNetworkPolicy.get_all_by_kwargs(f'_.name =~ "{str(self.cluster_id)}-.*"')

        # Shortcut
        if not self.all_netPols:
            self.logger.info("No network policies in cluster!")
            for source_pod in self.all_pods:
                for dest_pod in self.all_pods:
                    if source_pod.name != dest_pod.name:
                        self._create_connection(source_pod, dest_pod)
            return
        
        # match netPols to pods
        for pod in self.all_pods:
            pod.netPols = []
            pod.isolatedEgress = False
            pod.isolatedIngress = False

            pod_ns = sourcePod.name.split(":")[0]
            
            for netPol in self.all_netPols:
                netPol_ns = netPol.name.split(":")[0]

                # check if pol is in netPol NS
                if pod_ns != netPol_ns:
                    continue

                podSelector: client.V1LabelSelector = json.loads(netPol.pod_selector)

                # Creating netPol relationships to pods & checking for pod isolation
                if K8sDisc._eval_labelSelector(podSelector, pod):
                    netPol.applies_to.update(pod)
                    netPol.save()
                    # store for faster lookup
                    pod.netPols.append(netPol)

                    for policyType in netPol.spec.policy_types:
                        if policyType == "Ingress":
                            pod.isolatedIngress = True
                        if policyType == "Egress":
                            pod.isolatedEgress = True

        # check all pod pairs for connectivity
        for sourcePod in self.all_pods:
            for destPod in self.all_pods:
                if sourcePod is not destPod:
            
                    matchingEgress = False
                    matchingIngress = False
            
                    if sourcePod.isolatedEgress:
                        for netPol in sourcePod.netPols:
                            podSelector: client.V1LabelSelector = json.loads(netPol.pod_selector)
                            if K8sDisc._eval_labelSelector(podSelector, destPod):
                                matchingEgress = True
                                break
                    else:
                        matchingEgress = True

                    if destPod.isolatedIngress:
                        for netPol in destPod.netPols:
                            podSelector: client.V1LabelSelector = json.loads(netPol.pod_selector)
                            if K8sDisc._eval_labelSelector(podSelector, sourcePod):
                                matchingIngress = True
                                break
                    else:
                        matchingIngress = True

                    if matchingIngress and matchingEgress:
                        self._create_connection(sourcePod, destPod)

    def _create_connection(self, source_pod, dest_pod):
        """Create a CAN_CONNECT relationship from source to destination pod"""

        try:
            source_pod.can_connect_to.update(dest_pod)
            source_pod.save()
            self.logger.debug(f"Created CAN_CONNECT: {source_pod.name} -> {dest_pod.name}")
        except Exception as e:
            self.logger.error(f"Failed to create CAN_CONNECT relationship: {source_pod.name} -> {dest_pod.name}: {e}")


#######################################################
################### shit below ########################
#######################################################
#
#        # For each pod pair check if connection is allowed
#        for source_pod in self.all_pods:
#            for dest_pod in self.all_pods:
#                if source_pod.name != dest_pod.name:
#                    if self._is_connection_allowed(source_pod, dest_pod):
#                        self._create_connection(source_pod, dest_pod)
#
#
#    def _is_connection_allowed(self, source_pod, dest_pod):
#        """
#        Check if connection from source to dest is allowed.
#        1. Source pod's egress allows it (if source is egress-isolated)
#        2. Dest pod's ingress allows it (if dest is ingress-isolated)
#        """
#
#        # Check if source is egress-isolated (using pre-computed value)
#        if source_pod.egress_isolated:
#            # Source has egress restrictions, check if egress to dest is allowed
#            if not self._is_egress_allowed(source_pod, dest_pod):
#                return False
#
#        # Check if dest is ingress-isolated (using pre-computed value)
#        if dest_pod.ingress_isolated:
#            # Dest has ingress restrictions, check if ingress from source is allowed
#            if not self._is_ingress_allowed(source_pod, dest_pod):
#                return False
#
#        return True
#
#
#    def _is_pod_ingress_isolated(self, pod):
#        """
#        Check if a pod is ingress-isolated.
#        A pod is ingress-isolated if ANY NetworkPolicy in pod's namespace selects it and has 'Ingress' in policyTypes.
#        """
#        pod_ns = pod.name.split(":")[0]
#
#        for policy in self.all_netPols:
#            if policy.name.split(":")[0] != pod_ns:
#                continue
#
#            if self._policy_selects_pod(policy, pod):
#                policy_types = policy.policy_types if policy.policy_types else []
#                # Check if Ingress is explicitly in policyTypes
#                if "Ingress" in policy_types:
#                    return True
#                
#        return False
#
#
#    def _is_pod_egress_isolated(self, pod):
#        """
#        Check if a pod is egress-isolated.
#        A pod is egress-isolated if ANY NetworkPolicy in pod's namespace selects it and has 'Egress' in policyTypes.
#        """
#        pod_ns = pod.name.split(":")[0]
#
#        for policy in self.all_netPols:
#            if policy.name.split(":")[0] != pod_ns:
#                continue
#
#            if self._policy_selects_pod(policy, pod):
#                policy_types = policy.policy_types if policy.policy_types else []
#                # Check if Egress is explicitly in policyTypes
#                if "Egress" in policy_types:
#                    return True
#
#        return False
#
#
#    def _is_ingress_allowed(self, source_pod, dest_pod):
#        """
#        Check if ingress from source to dest is allowed by dest's ingress policies.
#        Policies are ADDITIVE: if ANY policy allows it, it's allowed.
#        """
#        dest_pod_ns = dest_pod.name.split(":")[0]
#
#        for policy in self.all_netPols:
#            policy_ns = policy.name.split(":")[0]
#            if policy_ns != dest_pod_ns:
#                continue
#
#            if not self._policy_selects_pod(policy, dest_pod):
#                continue
#
#            policy_types = policy.policy_types if policy.policy_types else []
#            if "Ingress" not in policy_types and not (policy.policy_types == [] and policy.ingress_rules):
#                continue
#
#            # Empty ingress rules with Ingress policyType = deny all
#            try:
#                ingress_rules = json.loads(policy.ingress_rules) if policy.ingress_rules else []
#            except Exception as e:
#                self.logger.warning(f"Failed to parse ingress_rules for policy {policy.name}: {e}")
#                ingress_rules = []
#            if not ingress_rules:
#                # Policy selects this pod and has Ingress in policyTypes but no rules = deny all for this policy
#                # Continue checking other policies
#                continue
#
#            for rule in ingress_rules:
#                from_selectors = rule.get("from", [])
#                if not from_selectors:
#                    return True
#
#                for selector in from_selectors:
#                    if self._pod_matches_peer_selector(source_pod, selector, policy_ns):
#                        return True
#
#        return False
#
#
#    def _is_egress_allowed(self, source_pod, dest_pod):
#        """
#        Check if egress from source to dest is allowed by source's egress policies.
#        Policies are ADDITIVE: if ANY policy allows it, it's allowed.
#        """
#        source_pod_ns = source_pod.name.split(":")[0]
#
#        for policy in self.all_netPols:
#            policy_ns = policy.name.split(":")[0]
#            if policy_ns != source_pod_ns:
#                continue
#
#            if not self._policy_selects_pod(policy, source_pod):
#                continue
#
#            policy_types = policy.policy_types if policy.policy_types else []
#            if "Egress" not in policy_types and not (policy.policy_types == [] and policy.egress_rules):
#                continue
#
#            # Empty egress rules with Egress policyType = deny all
#            try:
#                egress_rules = json.loads(policy.egress_rules) if policy.egress_rules else []
#            except Exception as e:
#                self.logger.warning(f"Failed to parse egress_rules for policy {policy.name}: {e}")
#                egress_rules = []
#            if not egress_rules:
#                # Policy selects this pod and has Egress in policyTypes but no rules = deny all for this policy
#                # Continue checking other policies
#                continue
#
#            for rule in egress_rules:
#                to_selectors = rule.get("to", [])
#                if not to_selectors:
#                    return True
#
#                for selector in to_selectors:
#                    if self._pod_matches_peer_selector(dest_pod, selector, policy_ns):
#                        return True
#
#        return False
#
#
#    def _ip_matches_cidr(self, ip, cidr, except_cidrs=None):
#        """
#        Check if an IP address matches a CIDR block, excluding exception CIDRs.
#
#        Args:
#            ip: IP address to check
#            cidr: CIDR block to match against
#            except_cidrs: List of CIDR blocks to exclude
#        """
#        try:
#            import ipaddress
#            ip_obj = ipaddress.ip_address(ip)
#            network = ipaddress.ip_network(cidr)
#
#            # Check if IP is in the main CIDR
#            if ip_obj not in network:
#                return False
#
#            # Check if IP is in any exception CIDR
#            if except_cidrs:
#                for except_cidr in except_cidrs:
#                    except_network = ipaddress.ip_network(except_cidr)
#                    if ip_obj in except_network:
#                        return False
#
#            return True
#        except Exception as e:
#            self.logger.warning(f"Failed to check IP {ip} against CIDR {cidr}: {e}")
#            return False
#
#    def _pod_matches_peer_selector(self, pod, peer_selector, policy_ns):
#        """
#        Check if a pod matches a network policy peer selector (from/to).
#
#        - podSelector alone: matches pods in policy's namespace only
#        - namespaceSelector alone: matches all pods in matching namespaces
#        - both: matches specific pods in matching namespaces
#        - ipBlock: matches pods based on their IP address (if available)
#        """
#        pod_ns = pod.name.split(":")[0]
#        pod_ns_obj = K8sNamespace.get_by_kwargs(f'_.name = "{pod_ns}"')
#
#        # Handle ipBlock
#        if "ipBlock" in peer_selector:
#            ip_block = peer_selector["ipBlock"]
#            cidr = ip_block.get("cidr")
#            except_cidrs = ip_block.get("except", [])
#
#            # Check if pod has an IP address
#            pod_ip = getattr(pod, 'pod_ip')
#            if pod_ip:
#                return self._ip_matches_cidr(pod_ip, cidr, except_cidrs)
#            else:
#                # If pod doesn't have IP info, we can't evaluate ipBlock rules
#                # Log a warning and conservatively deny
#                self.logger.debug(f"Pod {pod.name} has no IP address, cannot evaluate ipBlock rule")
#                return False
#
#        # Handle podSelector
#        if "podSelector" in peer_selector:
#            pod_selector = peer_selector["podSelector"].get("matchLabels", {})
#            pod_match_expressions = peer_selector["podSelector"].get("matchExpressions")
#
#            # If there's also a namespaceSelector, pod must be in matching namespace
#            if "namespaceSelector" in peer_selector:
#                ns_selector = peer_selector["namespaceSelector"].get("matchLabels", {})
#                ns_match_expressions = peer_selector["namespaceSelector"].get("matchExpressions")
#                if not pod_ns_obj or not self._namespace_matches_selector(pod_ns_obj, ns_selector, ns_match_expressions):
#                    return False
#            else:
#                # podSelector alone: only matches pods in the policy's own namespace
#                if pod_ns != policy_ns:
#                    return False
#
#            # Check if pod matches the pod selector
#            return self._pod_matches_selector(pod, pod_selector, pod_match_expressions)
#
#        # Handle namespaceSelector without podSelector
#        elif "namespaceSelector" in peer_selector:
#            ns_selector = peer_selector["namespaceSelector"].get("matchLabels", {})
#            ns_match_expressions = peer_selector["namespaceSelector"].get("matchExpressions")
#            if pod_ns_obj:
#                return self._namespace_matches_selector(pod_ns_obj, ns_selector, ns_match_expressions)
#
#        return False
#
#
#    def _matches_label_selector_expression(self, labels, match_expression):
#        """
#        Check if labels match a single matchExpression.
#        Supports operators: In, NotIn, Exists, DoesNotExist
#        """
#        key = match_expression.get("key")
#        operator = match_expression.get("operator")
#        values = match_expression.get("values", [])
#
#        if operator == "In":
#            return labels.get(key) in values
#        elif operator == "NotIn":
#            return labels.get(key) not in values
#        elif operator == "Exists":
#            return key in labels
#        elif operator == "DoesNotExist":
#            return key not in labels
#        else:
#            self.logger.warning(f"Unknown matchExpression operator: {operator}")
#            return False
#
#    def _pod_matches_selector(self, pod, selector, match_expressions=None):
#        """
#        Check if a pod matches a label selector.
#        None = none selected
#        {} = all selected
#        """
#        # Null selector matches no objects
#        if selector is None and (match_expressions is None or len(match_expressions) == 0):
#            return False
#
#        # Empty dict selector and no expressions matches all objects
#        if selector == {} and (match_expressions is None or len(match_expressions) == 0):
#            return True
#
#        try:
#            pod_labels = json.loads(pod.labels) if pod.labels else {}
#        except:
#            pod_labels = {}
#
#        # All selector labels must match (matchLabels)
#        if selector:
#            for key, value in selector.items():
#                if pod_labels.get(key) != value:
#                    return False
#
#        # All match expressions must match (matchExpressions)
#        if match_expressions:
#            for expr in match_expressions:
#                if not self._matches_label_selector_expression(pod_labels, expr):
#                    return False
#
#        return True
#
#    def _policy_selects_pod(self, policy, pod):
#        """Check if a network policy selects a specific pod"""
#        try:
#            pod_selector = json.loads(policy.pod_selector) if policy.pod_selector else None
#        except Exception as e:
#            self.logger.warning(f"Failed to parse pod_selector for policy {policy.name}: {e}")
#            pod_selector = {}
#        return self._pod_matches_selector(pod, pod_selector)
#
#
#    def _namespace_matches_selector(self, namespace, selector, match_expressions=None):
#        """
#        Check if a namespace matches a label selector.
#
#        Args:
#            namespace: The namespace to check
#            selector: Dict of matchLabels (all must match - AND logic). None = no match, {} = match all
#            match_expressions: List of matchExpressions (all must match - AND logic). None or [] = ignored
#
#        Note: An empty label selector (selector={} and no match_expressions) matches all objects.
#              A null label selector (selector=None and match_expressions=None) matches no objects.
#        """
#        # Null selector matches no objects
#        if selector is None and (match_expressions is None or len(match_expressions) == 0):
#            return False
#
#        # Empty dict selector and no expressions matches all objects
#        if selector == {} and (match_expressions is None or len(match_expressions) == 0):
#            return True
#
#        try:
#            ns_labels = json.loads(namespace.labels) if namespace.labels else {}
#        except Exception as e:
#            self.logger.warning(f"Failed to parse namespace labels for {namespace.name}: {namespace.labels}. Error: {e}")
#            ns_labels = {}
#
#        # All selector labels must match (matchLabels)
#        if selector:
#            for key, value in selector.items():
#                self.logger.debug(f"Trying namespace match: key={key}, value={value}, nsVal={ns_labels.get(key)}, nsLabels={ns_labels}, match?={ns_labels.get(key) == value}")
#                if ns_labels.get(key) != value:
#                    return False
#
#        # All match expressions must match (matchExpressions)
#        if match_expressions:
#            for expr in match_expressions:
#                if not self._matches_label_selector_expression(ns_labels, expr):
#                    return False
#
#        return True
#
