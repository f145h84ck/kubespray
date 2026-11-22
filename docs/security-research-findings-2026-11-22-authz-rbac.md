# Security research findings (2026-11-22) — AuthZ / Addon RBAC / kubelet

Commit reviewed: `ae89e4c4`. New HIGH issues **not** in the already-reported set (API kubelet serving TLS, terraform exposures, world-readable creds, Ceph/RBD/local-path/ALB/Azure/UpCloud/Cinder RBAC, metrics-server TLS, offline registry, dual-stack nginx, shell injections, ArgoCD downloads, EPEL HTTP GPG).

## Findings

### 1. Kubelet authorization defaults to AlwaysAllow while accepting ServiceAccount tokens (high) — ON BY DEFAULT

- **Primary file:** `roles/kubespray-defaults/defaults/main.yaml`
- **Evidence:** `roles/kubespray-defaults/defaults/main.yaml:477-480`, `roles/kubernetes/node/templates/kubelet-config.v1beta1.yaml.j2:5-16`, `roles/kubernetes/node/defaults/main.yml:5-6`, `roles/kubernetes/node/defaults/main.yml:26-31`, `roles/kubernetes/node/templates/kubelet.service.j2:27-31`
- **Default / opt-in:** ON BY DEFAULT (`kubelet_authorization_mode_webhook: false`, `kubelet_authentication_token_webhook: true`, `kubelet_bind_address` defaults to all interfaces, `kubelet_systemd_hardening: false`)
- **Attack path:**
  1. Operator deploys with stock defaults (no hardening overlay).
  2. Every kubelet serves HTTPS `:10250` on `0.0.0.0` with anonymous auth disabled but **TokenReview webhook auth enabled**, and `authorization.mode: AlwaysAllow`.
  3. Attacker who can run code in **any** pod (or reuse any ServiceAccount token) reaches the node kubelet on the pod network. No default-deny NetworkPolicy is installed; systemd IP allowlisting is off unless hardening is applied.
  4. SA bearer token authenticates; AlwaysAllow authorizes `pods/exec`, logs, port-forward, and runningPods on that node.
  5. Exec into a privileged/hostPath/CNI pod (PSA is off by default) → node root → read `/etc/kubernetes/admin.conf` on control-plane nodes → cluster-admin.
- **Impact:** Any workload foothold becomes node compromise and, on control-plane nodes, full cluster-admin.
- **Remediation:** Default `kubelet_authorization_mode_webhook: true`; enable `kubelet_systemd_hardening` with `kubelet_secure_addresses` limited to control-plane IPs (as in `docs/hardening.md`); keep anonymous auth false.
- **Distinct from reported #1:** #1 is apiserver→kubelet **serving-cert** MITM. This is kubelet **client authorization** AlwaysAllow for authenticated SA tokens.

### 2. Hetzner external CCM binds its ServiceAccount to cluster-admin and pulls `:latest` (high) — opt-in

- **Primary file:** `roles/kubernetes-apps/external_cloud_controller/hcloud/templates/external-hcloud-cloud-role-bindings.yml.j2`
- **Evidence:** `roles/kubernetes-apps/external_cloud_controller/hcloud/templates/external-hcloud-cloud-role-bindings.yml.j2:1-13`, `roles/kubernetes-apps/external_cloud_controller/hcloud/defaults/main.yml:6-8`, `roles/kubernetes-apps/external_cloud_controller/meta/main.yml:23-28`, contrast `roles/kubernetes-apps/external_cloud_controller/openstack/templates/external-openstack-cloud-controller-manager-role-bindings.yml.j2:7-10`
- **Default / opt-in:** Opt-in when `cloud_provider=external` and `external_cloud_provider=hcloud` (documented Hetzner path). RBAC is wildly excessive (`cluster-admin`).
- **Attack path:**
  1. Operator enables the Hetzner external cloud controller.
  2. Addon creates SA `cloud-controller-manager` bound to **cluster-admin** (OpenStack/vSphere paths use `system:cloud-controller-manager` instead) and deploys image tag `latest`.
  3. Attacker compromises the CCM pod (RCE / supply-chain on mutable `latest`) or creates a pod using that `serviceAccountName`.
  4. Immediate Kubernetes cluster-admin; Hetzner API token also present via the `hcloud` Secret env.
- **Impact:** CCM compromise is full cluster takeover, far beyond cloud-resource scope.
- **Remediation:** Bind to `system:cloud-controller-manager` (match OpenStack/vSphere); pin CCM image digest/tag; restrict `kube-system` pod creation.
- **Distinct from #21–24:** Those are ALB/CSI Secret/pod rules. This is a hard `cluster-admin` ClusterRoleBinding for the Hetzner CCM SA.

### 3. OCI CCM DaemonSet hostPath-mounts entire `/etc/kubernetes` (high) — opt-in

- **Primary file:** `roles/kubernetes-apps/cloud_controller/oci/templates/oci-cloud-provider.yml.j2`
- **Evidence:** `roles/kubernetes-apps/cloud_controller/oci/templates/oci-cloud-provider.yml.j2:50-72`, `roles/kubernetes-apps/cluster_roles/files/oci-rbac.yml:95-101`, `roles/kubernetes-apps/cluster_roles/tasks/oci.yml:1-19`, `roles/kubespray-defaults/defaults/main.yaml:139-148`
- **Default / opt-in:** Opt-in when `cloud_provider=oci`. Mounting host cluster-admin kubeconfig/PKI into a workload is wildly excessive.
- **Attack path:**
  1. Operator sets `cloud_provider: oci` and applies the OCI cloud controller.
  2. DaemonSet runs hostNetwork on control-plane nodes and mounts hostPath `/etc/kubernetes` read-only into the container (includes `admin.conf` and `ssl/` / PKI). No `securityContext.runAsNonRoot` is set.
  3. Attacker who compromises the OCI CCM container (or escapes into that mount namespace) reads `admin.conf` / CA material directly from the mount.
  4. Independently, OCI RBAC also grants cluster-wide `secrets` get/list to the same SA.
- **Impact:** CCM compromise yields immediate cluster-admin credentials from disk, plus Secret list and embedded OCI private key material (also written world-readable under `/etc/kubernetes` per known finding #5).
- **Remediation:** Use in-cluster ServiceAccount credentials only; do not mount `/etc/kubernetes`; if a kubeconfig is required, mount a dedicated least-privilege kubeconfig Secret; drop hostPath to host PKI.
- **Distinct from #5:** #5 is host filesystem permissions for local Unix users. This is projecting the control-plane credential directory into the CCM pod attack surface.

### 4. kube-vip static pod mounts host `admin.conf` (high) — opt-in

- **Primary file:** `roles/kubernetes/node/templates/manifests/kube-vip.manifest.j2`
- **Evidence:** `roles/kubernetes/node/templates/manifests/kube-vip.manifest.j2:75-91`, `roles/kubespray-defaults/defaults/main.yaml:63`, `roles/kubernetes/node/tasks/main.yml:20-25`
- **Default / opt-in:** Opt-in (`kube_vip_enabled: false`). Mounting cluster-admin kubeconfig is wildly excessive for VIP management.
- **Attack path:**
  1. Operator sets `kube_vip_enabled: true` (and typically control-plane VIP options).
  2. Static pod runs hostNetwork with `NET_ADMIN`/`NET_RAW` and mounts `/etc/kubernetes/admin.conf` from the host.
  3. Attacker compromises the kube-vip container (image RCE or adjacent hostNetwork attack).
  4. Reads mounted `admin.conf` → cluster-admin API access without needing a further host breakout.
- **Impact:** Container compromise of the VIP manager becomes full cluster-admin.
- **Remediation:** Mount a dedicated kubeconfig limited to the Lease/Endpoints permissions kube-vip needs; never mount `admin.conf`; pin image digests.
- **Distinct from #5 / #2:** Independent opt-in HA addon path that hands cluster-admin credentials to a network-privileged static pod.

## Explicitly checked — no new MEDIUM+ (or duplicate / incomplete chain)

- AWS EBS CSI secrets get/list only when `aws_ebs_csi_enable_volume_snapshot` (default false).
- GCP PD CSI: no cluster-wide secrets rules; PSP volumes `*` only relevant if PSP enabled (off by default).
- vSphere CSI: no secrets ClusterRole rules (insecure TLS already reported #10).
- OpenStack / vSphere external CCM: least-privilege `system:cloud-controller-manager` (includes secrets get/list/watch as upstream CCM pattern; not elevated to cluster-admin).
- Equinix/Hetzner CSI: not present as in-tree addon roles in this tree.
- Dashboard: restricted Role + metrics ClusterRole; `contrib/misc/clusteradmin-rbac.yml` is manual opt-in helper only.
- Helm: client binary install only (Helm 3); no Tiller.
- Registry addon: ClusterIP default; empty htpasswd does not complete an external unauth chain (offline helper registry already #15).
- ingress-nginx: secrets list/watch expected for TLS; admission webhook opt-in.
- MetalLB / netchecker / CoreDNS: no cluster-admin or pods*+secrets*.
- node-webhook ClusterRole only applied when webhook authz is enabled (off by default).
- PSA/PSP off: known hardening gap; incomplete without a separate pod-create foothold (not re-reported alone).
