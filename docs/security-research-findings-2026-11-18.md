# Security research findings (2026-11-18)

New HIGH-IMPACT default/configuration issues in this tree that are **not** duplicates of the already-known set:

1. kubelet authorization AlwaysAllow
2. Ansible host_key_checking=False
3. kubeadm control-plane join unsafeSkipCAVerification
4. AWS terraform IAM wildcards + SSH 0.0.0.0/0
5. kubeadm tokens leaked without no_log
6. PSP off / PSA defaults disabled

## Findings

### 1. UpCloud Terraform leaves public NICs unfirewalled (critical)

- **Primary file:** `contrib/terraform/upcloud/variables.tf`
- **Evidence:** `contrib/terraform/upcloud/variables.tf:59-62`, `contrib/terraform/upcloud/modules/kubernetes-cluster/main.tf:68-84`, `contrib/terraform/upcloud/modules/kubernetes-cluster/main.tf:125-141`, `contrib/terraform/upcloud/sample-inventory/cluster.tfvars:98-114`
- **Attack path:** Operator applies UpCloud terraform (defaults/`cluster-settings`). Every master and worker gets a **public** NIC while `firewall_enabled` defaults to `false`, so UpCloud applies no host firewall. Internet attackers reach SSH (and API/NodePorts) on the public addresses. After SSH as the configured user with become/root, read `/etc/kubernetes/admin.conf` (control plane) or etcd node client certs under `/etc/ssl/etcd/ssl` (workers; all `k8s_cluster` hosts receive etcd client certs) and take over the cluster.
- **Impact:** Remote root on every node and full cluster compromise without any Kubernetes foothold.
- **Remediation:** Default `firewall_enabled=true` with deny-by-default; restrict SSH/API source ranges; avoid public NICs on control-plane/etcd unless required.
- **Not a duplicate of #4:** Non-AWS provider; AWS finding was IAM wildcards + SG SSH. Here firewall is off entirely on public interfaces.

### 2. Hetzner Terraform sample defaults open SSH and API to the world (high)

- **Primary file:** `contrib/terraform/hetzner/default.tfvars`
- **Evidence:** `contrib/terraform/hetzner/default.tfvars:38-44`, `contrib/terraform/hetzner/modules/kubernetes-cluster/main.tf:74-89`
- **Attack path:** Operator copies `default.tfvars`, sets real SSH keys, applies. Firewalls allow TCP/22 and TCP/6443 from `0.0.0.0/0`. Internet SSH or use of a stolen low-priv kubeconfig against the public API, then escalate via missing PSA (known #6) or host access to `admin.conf`.
- **Impact:** Internet-wide SSH/API attack surface on a documented default inventory.
- **Remediation:** Default whitelists to empty/private CIDRs; fail apply if `0.0.0.0/0` remains for SSH.
- **Not a duplicate of #4:** Hetzner, not AWS.

### 3. Exoscale Terraform sample defaults open SSH and API to the world (high)

- **Primary file:** `contrib/terraform/exoscale/default.tfvars`
- **Evidence:** `contrib/terraform/exoscale/default.tfvars:59-65`, `contrib/terraform/exoscale/modules/kubernetes-cluster/main.tf:138-143`
- **Attack path:** Same pattern as Hetzner: sample defaults whitelist SSH/API from `0.0.0.0/0`; compromise SSH or abuse stolen kubeconfig on public API → cluster takeover.
- **Impact:** Internet exposure of management plane by default sample config.
- **Remediation:** Restrict `ssh_whitelist` / `api_server_whitelist` defaults; document required operator CIDRs.
- **Not a duplicate of #4:** Exoscale, not AWS.

### 4. OpenStack Terraform defaults open bastion SSH and API to 0.0.0.0/0 (high)

- **Primary file:** `contrib/terraform/openstack/variables.tf`
- **Evidence:** `contrib/terraform/openstack/variables.tf:217-227`, `contrib/terraform/openstack/modules/compute/main.tf:45-53`, `contrib/terraform/openstack/modules/compute/main.tf:74-82`
- **Attack path:** Defaults set `bastion_allowed_remote_ips` and `master_allowed_remote_ips` to `["0.0.0.0/0"]`. With a bastion (`number_of_bastions > 0`), SSH from the internet hits the bastion; with floating IPs on masters, API 6443 is internet-reachable. Stolen low-priv kubeconfig works from anywhere; SSH foothold yields root/`admin.conf`.
- **Impact:** World-reachable bastion SSH and/or Kubernetes API on default variables.
- **Remediation:** Default both lists to `[]` or private CIDRs; require explicit operator CIDRs.
- **Not a duplicate of #4:** OpenStack module defaults, not AWS IAM/SG.

### 5. Equinix Metal Terraform provisions publicly reachable root SSH with no firewall (high)

- **Primary file:** `contrib/terraform/metal/kubespray.tf`
- **Evidence:** `contrib/terraform/metal/kubespray.tf:11-22`, `contrib/terraform/metal/output.tf:1-14`, `contrib/terraform/metal/hosts:216-221`
- **Attack path:** Module creates Metal devices that publish `access_public_ipv4` and installs the operator SSH key. Inventory helper defaults `ansible_ssh_user` to `root`. No Metal firewall/ACL resources are defined. Internet SSH to root on masters/workers → read `admin.conf` / node credentials → cluster admin.
- **Impact:** Bare-metal nodes are globally SSH-reachable as root by default module design.
- **Remediation:** Add Metal firewall rules (SSH/API allowlists); prefer non-root user; optionally private networking only.
- **Not a duplicate of #4:** Equinix Metal, not AWS.

### 6. Hetzner external cloud-controller binds its SA to cluster-admin (high)

- **Primary file:** `roles/kubernetes-apps/external_cloud_controller/hcloud/templates/external-hcloud-cloud-role-bindings.yml.j2`
- **Evidence:** `roles/kubernetes-apps/external_cloud_controller/hcloud/templates/external-hcloud-cloud-role-bindings.yml.j2:1-13`, `roles/kubernetes-apps/external_cloud_controller/meta/main.yml:23-28`, `roles/kubespray-defaults/defaults/main.yaml:456-460`, `roles/kubernetes-apps/external_cloud_controller/openstack/templates/external-openstack-cloud-controller-manager-role-bindings.yml.j2:7-10` (contrast: OpenStack uses `system:cloud-controller-manager`)
- **Attack path:** Operator sets `cloud_provider=external` and `external_cloud_provider=hcloud`. Addon creates SA `cloud-controller-manager` bound to **cluster-admin** (not the dedicated CCM role). Attacker who can run code as that SA (compromise/RCE in the CCM pod, pull of mutable `controller_image_tag: latest`, or create a pod in `kube-system` using that `serviceAccountName`) receives full cluster-admin, plus the Hetzner API token from the `hcloud` secret.
- **Impact:** CCM compromise becomes immediate Kubernetes cluster-admin (far beyond cloud-resource scope).
- **Remediation:** Bind to `system:cloud-controller-manager` (as OpenStack/vSphere paths do); pin CCM image digests/tags; restrict who can create pods in `kube-system`.
- **Not a duplicate of #1/#6:** Independent RBAC misbind for the Hetzner addon; OpenStack/vSphere templates already use the least-privilege CCM role.

### 7. vSphere Terraform hardcodes allow_unverified_ssl (medium)

- **Primary file:** `contrib/terraform/vsphere/main.tf`
- **Evidence:** `contrib/terraform/vsphere/main.tf:1-10`
- **Attack path:** During `terraform apply`, TLS to vCenter is not verified. On-path attacker MITMs vSphere API, returns malicious VM templates/userdata, and provisions backdoored nodes that later receive kubeadm join credentials.
- **Impact:** Supply-chain compromise of all cluster nodes at provision time.
- **Remediation:** Default `allow_unverified_ssl=false`; make insecure TLS an explicit opt-in.
- **Not a duplicate of #2/#3:** Targets vSphere API TLS during infra provisioning, not Ansible SSH host keys or kubeadm join CA skip.

## Explicitly reviewed and not reported (incomplete chain or duplicate)

- `dashboard_enabled` default false; no default cluster-admin dashboard bind.
- `kube_read_only_port` default 0.
- `kube_api_anonymous_auth` true with RBAC only grants discovery/health (no extra anonymous CRBs found).
- `kube_encrypt_secret_data` false: etcd still requires client certs; realistic theft paths collapse into known #1/#6 or the terraform SSH findings above.
- `etcd_metrics_port` not set by default (metrics bind only when defined).
- Registry/netchecker/metrics-server/ingress/metallb/kube-vip disabled by default.
- Download URLs for kube binaries are HTTPS with checksums; `download_validate_certs` true.
- Controller-manager/scheduler `bind-address 0.0.0.0` is weaker than kubeadm/hardening.md but lacks an unauthenticated privilege-escalation chain on default 1.25 authn/authz kubeconfigs.
