# Security research findings (2026-11-20)

New MEDIUM+ issues that are **not** duplicates of the already-reported set:

Already reported (do not restate): AWS IAM wildcards + SSH 0.0.0.0/0; UpCloud public NICs unfirewalled; Hetzner/Exoscale/OpenStack terraform 0.0.0.0/0 SSH/API; Equinix Metal public root SSH; vSphere `allow_unverified_ssl`; Hetzner CCM cluster-admin; PSP off / PSA defaults disabled.

Focus of this pass: GCP terraform, AWS *distinct* paths, Azure (`contrib/azurerm`), remaining terraform, and kube-apps RBAC / insecure defaults for addons that are on by default or are common optional enablements.

## Findings

### 1. GCP Terraform defaults grant `cloud-platform` scopes on public nodes with no metadata protection (high)

- **Primary file:** `contrib/terraform/gcp/variables.tf`
- **Evidence:** `contrib/terraform/gcp/variables.tf:37-65`, `contrib/terraform/gcp/modules/kubernetes-cluster/main.tf:231-246`, `contrib/terraform/gcp/modules/kubernetes-cluster/main.tf:337-352`, `contrib/terraform/gcp/README.md:82-91`, `contrib/terraform/gcp/README.md:97-99`
- **Attack path:**
  1. Operator applies `contrib/terraform/gcp` with defaults (`master_sa_scopes` / `worker_sa_scopes` = `https://www.googleapis.com/auth/cloud-platform`; empty `*_sa_email` → project **default Compute Engine SA**, typically Project Editor).
  2. Every master and worker gets a public NAT IP (`access_config`); README states bastion is unsupported so public IPs are required.
  3. No `metadata` keys for OS Login / block-project-ssh-keys / GCE metadata concealment; kubespray does not install host firewall rules denying pod→`169.254.169.254`.
  4. Attacker with any pod exec/SSRF (or host foothold) queries the metadata server for an access token (`Metadata-Flavor: Google`).
  5. Token carries **cloud-platform** scope as the default CE SA → create VMs, alter firewalls (e.g. open SSH), read disks/secrets in GCP, and pivot to full project (and often cluster) compromise.
- **Impact:** Workload/SSRF foothold becomes full GCP project takeover; far beyond node-scoped cloud API needs.
- **Remediation:** Default scopes to least privilege (e.g. `devstorage.read_only`, `logging.write`, `monitoring.write`, `compute` only if CCM needs it); create dedicated locked-down SAs per role; enable metadata concealment / disable legacy endpoints; prefer private nodes + bastion; restrict metadata via network policy/iptables.
- **Not a duplicate:** GCP provider; prior cloud findings were SSH/API CIDR opens or Hetzner CCM RBAC, not GCE SA scope + metadata token theft.

### 2. Azure ARM templates (`contrib/azurerm`) open SSH and kube-apiserver to the Internet by default (high)

- **Primary file:** `contrib/azurerm/roles/generate-templates/templates/network.json`
- **Evidence:** `contrib/azurerm/group_vars/all:8` (`use_bastion: false`), `contrib/azurerm/roles/generate-templates/templates/network.json:73-101`, `contrib/azurerm/roles/generate-templates/templates/masters.json:19-28` (public API LB), `contrib/azurerm/roles/generate-templates/templates/masters.json:88-120` / `minions.json:12-42` (per-node public IPs when not using bastion), `contrib/azurerm/roles/generate-templates/templates/bastion.json:26-49` (bastion NIC has **no** NSG)
- **Attack path:**
  1. Operator runs `generate-templates` / `apply-rg` with sample `group_vars/all` (`use_bastion: false`).
  2. NSG allows **Inbound TCP/22 and TCP/6443 from `Internet`**; masters, minions, and the kubernetes-api public LB all become internet-reachable.
  3. Internet SSH to any node (sample also ships a real `ssh-rsa` key under `ssh_public_keys` that must be replaced — forgetting that leaves a third-party authorized key). After SSH + become, read `/etc/kubernetes/admin.conf` → cluster-admin.
  4. Independently, kube-apiserver via public LB accepts connections from anywhere (auth still required, but stolen/leaked kubeconfig or token works globally; pairs with known PSA-off for escalation).
  5. Even if `use_bastion: true`, the kube-api Internet rule remains, and the bastion NIC is created **without** an NSG (Azure allow-all inbound on the bastion public IP).
- **Impact:** Internet-wide SSH and Kubernetes API exposure on the documented Azure path; bastion mode does not actually isolate management.
- **Remediation:** Default deny; require explicit source CIDRs for SSH/API; attach a locked-down NSG to bastion; default `use_bastion: true` without node public IPs; remove committed sample SSH keys / force operator-supplied keys.
- **Not a duplicate:** Azure (`contrib/azurerm`) was not in the prior provider list (AWS/UpCloud/Hetzner/Exoscale/OpenStack/Metal/vSphere).

### 3. AWS Terraform publishes an internet-facing NLB for kube-apiserver (high) — distinct from SSH/IAM finding

- **Primary file:** `contrib/terraform/aws/modules/nlb/main.tf`
- **Evidence:** `contrib/terraform/aws/modules/nlb/main.tf:2-12` (NLB in **public** subnets, no `internal = true`), `contrib/terraform/aws/modules/nlb/main.tf:15-20` (`target_type = "ip"`), `contrib/terraform/aws/create-infrastructure.tf:75-103` (masters in private subnets registered by private IP), `contrib/terraform/aws/modules/vpc/main.tf:112-118` (SG allows all protocols from VPC CIDR only — not from `0.0.0.0/0` on 6443)
- **Attack path:**
  1. Operator applies AWS terraform defaults: internet-facing NLB listens on 6443 and forwards to master private IPs.
  2. For IP-target TCP NLBs, client IP preservation defaults to **off** (IPv4), so packets arrive on masters sourced from NLB ENIs inside the VPC CIDR.
  3. Instance SG allows all traffic from the VPC CIDR → internet clients reach kube-apiserver through the public NLB **without** any `0.0.0.0/0` rule on port 6443.
  4. Attacker uses anonymous/discovery probes, exploits apiserver CVEs, or replays a stolen kubeconfig/token from anywhere; combine with known PSA-disabled defaults for privilege escalation.
- **Impact:** Control-plane API is globally reachable despite masters living in “private” subnets; bypasses the apparent SG posture.
- **Remediation:** Set `internal = true` (or private subnets only) by default; if a public API is required, enable client-IP preservation and restrict SG/NLB source CIDRs explicitly; prefer private API + bastion/VPN.
- **Not a duplicate of AWS IAM+SSH:** That finding is wildcard IAM and SG SSH/22. This is a separate path: public NLB → API/6443 via VPC-sourced packets.

### 4. AWS Terraform leaves IMDSv1 enabled on all instances (medium) — distinct credential-theft path

- **Primary file:** `contrib/terraform/aws/create-infrastructure.tf`
- **Evidence:** `contrib/terraform/aws/create-infrastructure.tf:52-149` (`aws_instance` for bastion/master/etcd/worker with **no** `metadata_options` / `http_tokens = "required"`), plus known broad instance profiles in `contrib/terraform/aws/modules/iam/main.tf`
- **Attack path:**
  1. Cluster runs with default instance metadata (IMDSv1 still accepted).
  2. Attacker obtains SSRF or pod network access to `169.254.169.254` (no hop-limit/session-token requirement).
  3. Retrieves IAM role credentials from IMDS and exercises the (already overly broad) node/control-plane policies — including `ec2:*` / `elasticloadbalancing:*` on masters.
- **Impact:** Low-complexity cloud credential theft from workloads/SSRF, amplifying IAM abuse without needing host SSH.
- **Remediation:** Set `metadata_options { http_endpoint = "enabled", http_tokens = "required", http_put_response_hop_limit = 1 }` on all instances; block pod IMDS via iptables/network policy.
- **Not a duplicate of AWS IAM+SSH:** IAM finding covers permission breadth and SSH exposure; IMDSv1 is a distinct theft primitive that works without SSH.

### 5. CephFS / RBD provisioners grant cluster-wide `secrets` mutate permissions (high, when enabled)

- **Primary files:** `roles/kubernetes-apps/external_provisioner/cephfs_provisioner/templates/clusterrole-cephfs-provisioner.yml.j2`, `roles/kubernetes-apps/external_provisioner/rbd_provisioner/templates/clusterrole-rbd-provisioner.yml.j2`
- **Evidence:** CephFS ClusterRole `secrets` verbs `get/create/delete` (cluster-scoped); RBD ClusterRole same; defaults `cephfs_provisioner_enabled: false` / `rbd_provisioner_enabled: false` in `roles/kubespray-defaults/defaults/main.yaml` and sample `addons.yml`, but sample comments document enabling them with placeholder secrets (`cephfs_provisioner_secret: secret`, `rbd_provisioner_secret: ceph-key-admin`).
- **Attack path:**
  1. Operator enables `cephfs_provisioner_enabled` or `rbd_provisioner_enabled` (common storage addon path).
  2. Provisioner SA is bound to a ClusterRole that can **get/create/delete Secrets in all namespaces**.
  3. Attacker who can exec into the provisioner pod, or create a pod using that SA (e.g. via weaker NS access / supply chain), reads `kubernetes-dashboard` tokens, cloud CCM secrets, or service-account tokens → escalate to cluster-admin; or plants secrets for persistence.
- **Impact:** Storage addon compromise → full cluster secret exfiltration / takeover.
- **Remediation:** Scope secret access to the provisioner namespace (Role, not ClusterRole) and only required secret names; drop `create/delete` if unused; prefer CSI drivers with tighter RBAC.
- **Not a duplicate:** Independent of Hetzner CCM cluster-admin bind; these are optional storage roles with secrets wildcards.

### 6. Local path provisioner ClusterRole allows `pods: ["*"]` cluster-wide (high, when enabled)

- **Primary file:** `roles/kubernetes-apps/external_provisioner/local_path_provisioner/templates/local-path-storage-cr.yml.j2`
- **Evidence:** `local-path-storage-cr.yml.j2:10-12` (`resources: ["endpoints", "persistentvolumes", "pods"]`, `verbs: ["*"]`); PSP template allows `privileged` + `hostPath` (`local-path-storage-psp.yml.j2`); helper pod config creates hostPath-style directory ops (`local-path-storage-cm.yml.j2`); `local_path_provisioner_enabled: false` by default but prominently documented in sample `addons.yml`.
- **Attack path:**
  1. Operator sets `local_path_provisioner_enabled: true`.
  2. Attacker compromises the provisioner SA (RCE in provisioner image, or create pod with that `serviceAccountName`).
  3. Uses cluster-wide `pods/*` to create a privileged/hostPath pod on a chosen node → root on the node → `admin.conf` / node kubelet creds → cluster-admin.
- **Impact:** Storage provisioner SA is effectively a cluster privilege-escalation gadget.
- **Remediation:** Limit pod verbs to `get/list/watch/create/delete` in the provisioner namespace only; tighten helper pod template (non-root, no privileged PSP); avoid cluster-scoped `pods:*`.
- **Not a duplicate:** Not covered by prior CCM/terraform findings.

### 7. Metrics Server defaults to `--kubelet-insecure-tls` and `insecureSkipTLSVerify` (medium, when enabled)

- **Primary file:** `roles/kubernetes-apps/metrics_server/defaults/main.yml`
- **Evidence:** `metrics_server_kubelet_insecure_tls: true` in defaults; deployment adds `--kubelet-insecure-tls` (`metrics-server-deployment.yaml.j2:43-44`); APIService sets `insecureSkipTLSVerify: {{ metrics_server_kubelet_insecure_tls }}` (`metrics-apiservice.yaml.j2:13`); sample `addons.yml` comments show the insecure flag as the documented setting; `metrics_server_enabled: false` by default but metrics-server is a commonly enabled addon for HPA/dashboard.
- **Attack path:**
  1. Operator enables `metrics_server_enabled: true` without overriding TLS settings.
  2. Metrics Server does not verify kubelet certificates; aggregated APIService also skips TLS verify to the metrics-server service.
  3. On-path attacker between metrics-server and kubelets (or to the metrics service) spoofs metrics / MITMs the aggregation path, enabling false autoscaling signals or forged resource metrics used by controllers/operators.
- **Impact:** Integrity loss for cluster metrics and autoscaling decisions; weakens aggregated API TLS.
- **Remediation:** Default `metrics_server_kubelet_insecure_tls: false`; use proper kubelet serving certs / CA; separate APIService TLS verify from kubelet scrape settings.
- **Not a duplicate:** Prior pass skipped because disabled by default; this records the insecure **default of the role** that applies whenever the common addon is turned on.

## Explicitly reviewed — no new MEDIUM+ (or out of scope)

| Area | Result |
| --- | --- |
| OCI terraform | Not present under `contrib/terraform` |
| GCP SSH/API sample whitelists | Sample uses `1.2.3.4/32` (not world-open); `ingress_whitelist` defaults to `0.0.0.0/0` for 80/443 only — expected ingress exposure, not reported alone |
| kube-vip | `kube_vip_enabled: false`; ARP/BGP off |
| Calico (default CNI) | VXLAN backend; `calico_wireguard_enabled: false`; encryption not expected for default VXLAN; `typha_enabled: false` (so `typha_secure: false` inert); `calico_healthhost: localhost` |
| Weave / flannel encryption | Not default plugin (`kube_network_plugin: calico`) |
| ingress-nginx / cert-manager / dashboard / helm | All disabled by default; dashboard `dashboard_skip_login: false`; no tiller (Helm 3); dashboard SA is not cluster-admin |
| Registry RBAC | PSP `use` only when enabled — not MEDIUM+ |
| Hetzner CCM cluster-admin | Already reported |

Defaults confirmed from `inventory/sample/group_vars/k8s_cluster/addons.yml` and `roles/kubespray-defaults/defaults/main.yaml` (`dashboard_enabled`, `helm_enabled`, `metrics_server_enabled`, `ingress_nginx_enabled`, `cert_manager_enabled`, provisioners, `kube_vip_enabled` all false; `kube_network_plugin: calico`).
