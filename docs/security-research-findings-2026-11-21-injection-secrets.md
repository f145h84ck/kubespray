# Security research findings (2026-11-21) — injection / secrets / logic

Commit reviewed: `ae89e4c4`. Scope: roles/** (not extra_playbooks), contrib/inventory_builder, contrib/aws_inventory, library/, scripts/, recover/reset/remove/scale/upgrade/cluster playbooks, ansible.cfg, and priority roles.

Already-known / previously flagged issues were not re-reported.

## New MEDIUM+ findings

### 1. HIGH — Dual-stack nginx localhost API proxy binds all IPv6 interfaces

- **Primary file:** `roles/kubernetes/node/templates/loadbalancer/nginx.conf.j2`
- **Evidence:** `roles/kubernetes/node/templates/loadbalancer/nginx.conf.j2:21-28`, `roles/kubernetes/node/tasks/main.yml:27-32`, `roles/kubespray-defaults/defaults/main.yaml:209`, `roles/kubespray-defaults/defaults/main.yaml:544-545`, `roles/kubernetes/node/templates/manifests/nginx-proxy.manifest.j2:12`, `docs/vars.md` (dual-stack)
- **Attack path:**
  1. Operator enables documented `enable_dual_stack_networks: true` with default `loadbalancer_apiserver_localhost` + `loadbalancer_apiserver_type: nginx`.
  2. `cluster.yml` deploys hostNetwork `nginx-proxy` on every worker (`not is_kube_master`).
  3. Rendered config keeps IPv4 on `127.0.0.1` but adds `listen [::]:{{port}}` (all IPv6 addresses), not `[::1]`.
  4. Attacker who can reach any worker’s IPv6 address on the API port reaches the real kube-apiserver via TCP proxy — using stolen tokens/kubeconfig, unauthenticated discovery/health, or API CVEs — bypassing the localhost-only LB design.
- **Impact:** Every dual-stack worker becomes a cluster-wide kube-apiserver front door on IPv6.
- **Remediation:** Bind IPv6 to `[::1]` (mirror IPv4 localhost). Add a regression test for dual-stack nginx listen addresses.
- **Why not duplicate:** Not in the known list; HAProxy path correctly binds only `127.0.0.1`; prior reviews dismissed stub_status info disclosure only.

### 2. HIGH — `recover-control-plane` shells inventory hostnames into `rm`

- **Primary file:** `roles/recover_control_plane/etcd/tasks/main.yml`
- **Evidence:** `roles/recover_control_plane/etcd/tasks/main.yml:45-51`, `recover-control-plane.yml:15-27` (etcd recover runs before `include: cluster.yml` hostname asserts), `roles/kubernetes/preinstall/tasks/0020-verify-settings.yml:147-151` (hostname assert only in preinstall)
- **Attack path:**
  1. Attacker poisons inventory so `broken_etcd` contains a hostname with shell metacharacters (forged inventory, malicious inventory_builder/`load` YAML, or compromised CI inventory).
  2. Operator runs `recover-control-plane.yml`.
  3. Task `shell: "rm {{ etcd_cert_dir }}/*{{ item }}*"` runs as root on `etcd[0]` **before** cluster preinstall hostname validation.
  4. Injected commands execute with root on the healthy etcd member → steal CA keys / wipe etcd / implant persistence → cluster takeover.
- **Impact:** Root RCE on etcd during recovery from inventory-controlled hostnames.
- **Remediation:** Use `file`/`find` modules or `command` with argv; validate hostnames before any shell; never interpolate inventory names into shell strings.
- **Why not duplicate:** Distinct from known inventory_builder `shell=True`+`access_ip`; this is playbook-side injection on the recover path.

### 3. HIGH — Etcd/remove-node shell interpolates `access_ip` / `etcd_member_name` / `node_ip`

- **Primary file:** `roles/etcd/tasks/configure.yml`
- **Evidence:** `roles/etcd/tasks/configure.yml:128-145`, `roles/etcd/tasks/join_etcd_member.yml:1-29`, `roles/remove-node/remove-etcd-node/tasks/main.yml:14-28`, `roles/kubespray-defaults/defaults/main.yaml:578-603`, `roles/kubernetes/preinstall/tasks/0020-verify-settings.yml:119-124` (ping uses `command`, not IP-format assert; skippable via `ping_access_ip: false`)
- **Attack path:**
  1. Inventory sets `access_ip` (or `etcd_member_name`) containing shell metacharacters. Sample inventories document disabling `ping_access_ip` when ICMP is blocked; with ping skipped there is no IP-shape validation. `etcd_member_name` is explicitly documented as inventory-settable and is never character-validated.
  2. `cluster.yml` / `scale.yml` / `remove-node.yml` run etcd configure/join/remove tasks.
  3. Unquoted interpolation into `shell:` (`grep -q {{ etcd_access_address }}`, `etcdctl member add {{ etcd_member_name }} --peer-urls=...`, `grep {{ node_ip }}`) executes attacker commands as root on etcd hosts.
  4. Attacker obtains root on etcd/control-plane → cluster CA and full compromise.
- **Impact:** Root RCE on etcd nodes during normal cluster/scale/remove operations from inventory fields.
- **Remediation:** Prefer `command` with separate argv; quote/validate `access_ip` as IP; restrict `etcd_member_name` to `[a-z0-9-]+`.
- **Why not duplicate:** Different sink than inventory_builder’s Python `shell=True`; sinks are core etcd/remove-node roles on the default deploy path.

### 4. MEDIUM — ArgoCD addon downloads `yq` and install manifests without checksums

- **Primary file:** `roles/kubernetes-apps/argocd/tasks/main.yml`
- **Evidence:** `roles/kubernetes-apps/argocd/tasks/main.yml:1-31`, `roles/kubespray-defaults/defaults/main.yaml:413` (`argocd_enabled: false`)
- **Attack path:**
  1. Operator enables `argocd_enabled`.
  2. Playbook `get_url`s GitHub `yq` binary and `argoproj/argo-cd` `manifests/install.yaml` with no `checksum`.
  3. On-path MITM (or compromised CDN/GitHub path) returns a trojan `yq` and/or manifests granting cluster-admin.
  4. Root on the control-plane node runs malicious `yq`; `kube` apply installs attacker controllers → cluster-admin.
- **Impact:** Supply-chain compromise of control plane when ArgoCD addon is enabled.
- **Remediation:** Pin SHA256 for `yq` and manifests (or vendor manifests in-repo); verify before execute/apply.
- **Why not duplicate:** Distinct from known NVIDIA HTTP driver checksum skip; ArgoCD was not previously flagged.

### 5. MEDIUM — Amazon Linux EPEL enables HTTP baseurl and HTTP GPG key when `epel_enabled`

- **Primary file:** `roles/bootstrap-os/tasks/bootstrap-amazon.yml`
- **Evidence:** `roles/bootstrap-os/tasks/bootstrap-amazon.yml:1-13`, `roles/kubespray-defaults/defaults/main.yaml:83` (`epel_enabled: false`)
- **Attack path:**
  1. Operator sets `epel_enabled: true` on Amazon Linux.
  2. Bootstrap writes yum repo with `baseurl: http://download.fedoraproject.org/...` and `gpgkey: http://download.fedoraproject.org/.../RPM-GPG-KEY-EPEL-7`.
  3. Network attacker MITMs both the key and packages (HTTP GPG key fetch defeats `gpgcheck: yes`).
  4. Subsequent package installs from EPEL run attacker RPMs as root → host and cluster compromise.
- **Impact:** Trusted package-supply-chain takeover on Amazon Linux bootstrap when EPEL is enabled.
- **Remediation:** Use HTTPS for baseurl and gpgkey; pin/import the EPEL key out-of-band.
- **Why not duplicate:** Not the NVIDIA driver finding; Amazon bootstrap path was not previously flagged.

## Checked — no new MEDIUM+ (or duplicate / opt-in weak chain)

- `ansible.cfg` `host_key_checking=False` (known)
- Fact caching `jsonfile` → `/tmp`: files created via `mkstemp` are mode `0600` (cross-user read blocked; below MEDIUM bar)
- `credentials_dir` / `artifacts` kubeconfig copy: `0600` files, `0750` artifacts dir; `.gitignore` covers `credentials/`
- `library/kube.py`: argv list via `run_command` — no shell injection
- `kube-gen-token.sh`: `/dev/urandom` tokens; token dir `o-rwx`; `kube_token_auth` default `false`
- `download_validate_certs: true`; binary downloads use sha256 maps; image digests optional (`default(None)`) but pulled over registry TLS
- cri-o: installs from checksummed archive; HTTP kubic repos only in cleanup/reset `state: absent`
- containerd/docker insecure registries: empty/unset by default
- webhook TLS skip defaults `false`; weave password default only (weave not default CNI)
- Calico default VXLAN, wireguard off, typha off; BGP router peering opt-in (`peer_with_router`)
- Flannel/canal unencrypted VXLAN expected; Cilium Hubble default off; kube-ovn/kube-router/kube-vip default off
- nginx `stub_status` only if healthcheck port defined — info disclosure only
- etcd client/peer URLs use HTTPS + cert auth; metrics bind only if `etcd_metrics_port` set
- `kube_encrypt_secret_data: false` — no new theft path beyond already-reported host secret exposure
- contrib/aws_inventory: no shell; tag-driven inventory only
- scripts/premoderator: disabled/`only: []` historically; token-in-URL is CI-side
- World-readable `/etc/kubernetes` secrets / missing `no_log` / inventory_builder `shell=True` — already known
