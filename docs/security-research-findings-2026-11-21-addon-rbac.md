# Security research findings (2026-11-21) — kubernetes-apps addon RBAC

Commit reviewed: `ae89e4c4` (branch `cursor/security-findings-persistence-12dc`).

Focus: `roles/kubernetes-apps/**` ClusterRoles/Bindings, ServiceAccounts, privileged pods, insecure defaults for documented addons (ingress_nginx, cert_manager, argocd, metallb, snapshots, local_volume_provisioner, registry, dashboard, netchecker, coredns, cluster_roles, policy_controller, csi_driver, alb).

Already-known issues were **not** re-reported (Hetzner CCM cluster-admin, CephFS/RBD secrets mutate, local-path pods:*, metrics-server insecure TLS, vSphere insecure TLS, NVIDIA HTTP driver, Heketi HTTP admin key, world-readable `/etc/kubernetes` secrets, PSP/PSA off, kubelet AlwaysAllow).

## New MEDIUM+ findings

### 1. HIGH — ALB Ingress ClusterRole can create/update pods and secrets cluster-wide

- **Primary file:** `roles/kubernetes-apps/ingress_controller/alb_ingress_controller/templates/alb-ingress-clusterrole.yml.j2`
- **Evidence:** `alb-ingress-clusterrole.yml.j2:8-10`, `alb-ingress-clusterrolebinding.yml.j2:1-14`, `inventory/sample/group_vars/k8s_cluster/addons.yml:128-129`, `roles/kubernetes-apps/ingress_controller/meta/main.yml:17-18`
- **Attack path:**
  1. Operator sets `ingress_alb_enabled: true` (documented sample addons path).
  2. Addon binds SA `alb-ingress` in `kube-system` to ClusterRole `alb-ingress`, which grants `pods` and `secrets` `create`/`update`/`patch`/`get`/`list`/`watch` in every namespace.
  3. Attacker compromises the ALB controller pod (RCE/image) or creates a pod using `serviceAccountName: alb-ingress`.
  4. With PSA/PSP off by default, attacker creates a privileged/hostPath pod on a control-plane node, reads `/etc/kubernetes/admin.conf` → cluster-admin; alternatively lists/updates Secrets (cloud creds, TLS keys).
- **Impact:** ALB addon compromise → immediate pod escape path to node root / cluster-admin, plus cluster-wide Secret theft and planting.
- **Why not a duplicate:** Distinct from CephFS/RBD (storage provisioner secrets mutate) and local-path (`pods:*`). This is the AWS ALB ingress addon with both **pods create** and **secrets mutate**.

### 2. HIGH — Azure Disk CSI grants cluster-wide Secret get/list to node DaemonSet (Owner cloud creds)

- **Primary file:** `roles/kubernetes-apps/csi_driver/azuredisk/templates/azure-csi-azuredisk-node-rbac.yml.j2`
- **Evidence:** `azure-csi-azuredisk-node-rbac.yml.j2:9-30`, `azure-csi-azuredisk-controller-rbac.yml.j2:132-139` and `:209-230`, `azure-csi-azuredisk-node.yml.j2:20-26,118-129`, `azuredisk/defaults/main.yml:4`, `docs/azure-csi.md:77-83`, `inventory/sample/group_vars/all/azure.yml:37-40`
- **Attack path:**
  1. Operator enables `azure_csi_enabled: true` and follows `docs/azure-csi.md`, which instructs creating an AAD app with Azure **Owner** and storing `aadClientSecret` in the `cloud-config` Secret.
  2. Every node runs privileged `csi-azuredisk-node` (hostNetwork, `/dev` + kubelet hostPath) as `csi-azuredisk-node-sa`, bound to a ClusterRole with `secrets` `get`/`list` in **all** namespaces (not limited to `cloud-config`). Controller SA gets the same cluster-wide Secret read (duplicate secret role + snapshotter).
  3. Role default `azure_csi_plugin_image_tag: latest` pulls a floating tag for the privileged plugin.
  4. Attacker who compromises any node CSI pod (vuln, malicious `:latest` image, or SA token theft) calls the API to list Secrets cluster-wide, steals `cloud-config` (Owner credentials) and workload secrets → Azure subscription takeover and cluster escalation.
- **Impact:** Documented Azure CSI path places cluster-wide Secret readers on every node next to Owner-scoped cloud credentials.
- **Why not a duplicate:** Not CephFS/RBD mutate RBAC; not world-readable host files under `/etc/kubernetes`. This is live Kubernetes RBAC on the Azure CSI node DaemonSet.

### 3. HIGH — UpCloud CSI provisioner ClusterRole lists Secrets cluster-wide

- **Primary file:** `roles/kubernetes-apps/csi_driver/upcloud/templates/upcloud-csi-setup.yml.j2`
- **Evidence:** `upcloud-csi-setup.yml.j2:42-49`, `upcloud-csi-cred-secret.yml.j2:1-9`, `inventory/sample/group_vars/all/upcloud.yml:4`, `roles/kubespray-defaults/defaults/main.yaml:402`
- **Attack path:**
  1. Operator sets `upcloud_csi_enabled: true` (sample `group_vars/all/upcloud.yml`) and supplies `upcloud_username` / `upcloud_password`.
  2. Addon creates Secret `upcloud` in `kube-system` and binds `csi-upcloud-controller-sa` to ClusterRole rules that allow `secrets` `get`/`list` with no namespace or `resourceNames` limit.
  3. Attacker compromises the CSI controller (or uses that SA) and lists Secrets in all namespaces, including the UpCloud API password and other app/cloud secrets.
  4. Stolen UpCloud credentials manipulate volumes/infra; stolen cluster Secrets escalate further.
- **Impact:** Enabling UpCloud CSI yields a cluster-wide Secret oracle from the provisioner SA.
- **Why not a duplicate:** Different provider/addon than Ceph/Azure; read-only but still cluster-scoped Secret access on a documented CSI enable path.

### 4. MEDIUM — Cinder CSI always binds snapshotter Secret get/list cluster-wide

- **Primary file:** `roles/kubernetes-apps/csi_driver/cinder/templates/cinder-csi-controllerplugin-rbac.yml.j2`
- **Evidence:** `cinder-csi-controllerplugin-rbac.yml.j2:99-135`, `cinder/tasks/main.yml:29-40`, `inventory/sample/group_vars/k8s_cluster/addons.yml:60-63`, `docs/cinder-csi.md:5-7`
- **Attack path:**
  1. Operator enables `cinder_csi_enabled: true` (documented); Kubespray always applies the controller RBAC that includes `csi-snapshotter-role`.
  2. That ClusterRole grants `secrets` `get`/`list` cluster-wide and is bound to `csi-cinder-controller-sa`.
  3. Compromising the Cinder CSI controller (or reusing its SA) lists Secrets across namespaces (OpenStack cloud-config plus workload secrets).
- **Impact:** Secret confidentiality loss and credential theft when Cinder CSI is enabled; quieter than Ceph mutate but still cluster-wide read.
- **Why not a duplicate:** Not Ceph create/delete; AWS EBS gates snapshotter secrets behind `aws_ebs_csi_enable_volume_snapshot` (default false). Cinder ships the Secret-read rule unconditionally.

## Reviewed, no new MEDIUM+ (or duplicate / by-design)

| Area | Notes |
|------|--------|
| ingress_nginx | ClusterRole is mostly list/watch; secrets list/watch expected for TLS; webhook ValidatingWebhookConfiguration update is opt-in (`ingress_nginx_webhook_enabled: false`) |
| cert_manager | Upstream-style Secret create/delete for certificates; expected for the product |
| argocd | Downloads pinned-version `install.yaml` over HTTPS; admin password task hashes before shell (no clear plaintext no_log gap beyond already-reported logging issues) |
| metallb | Secrets limited to `memberlist` in namespace Role |
| snapshots controller | No Secrets rules |
| local_volume_provisioner | Privileged + `/dev` by design; ClusterRole is PV/StorageClass scoped (no `pods:*` — that is local-path, already flagged) |
| registry | Default ClusterIP + empty htpasswd; weak but incomplete external chain |
| dashboard | Namespace Role + metrics ClusterRole only; `dashboard_skip_login` default false |
| netchecker | Pods get/list only; hostNetwork agent for connectivity checks |
| coredns / dns-autoscaler | Least-privilege read/scale |
| policy_controller (Calico) | CRD/node/pod watch as expected |
| cluster_roles | OCI CCM secrets get/list when `cloud_provider=oci` (CCM-typical); node-webhook only when webhook kubelet auth |
| aws_ebs / gcp_pd / vsphere CSI | No unconditional cluster-wide Secret list on node SA; EBS snapshot secrets are opt-in |
| GCP PD / Azure/UpCloud privileged node plugins | Privileged CSI node is expected; RBAC overreach called out above where present |
