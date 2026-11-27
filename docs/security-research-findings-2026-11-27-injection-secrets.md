# Security research findings (2026-11-27) — injection / crypto / secrets

Commit reviewed: `73c39fc12f17060a30ea884c51f82481676d01b2`. Scope: remaining shell/raw injection of inventory/cloud-derived fields, get_url checksum gaps, remaining `no_log` that leaks **different** secrets than findings 6/42/43, unsigned HTTP downloads of privileged code not covered by 19/20/26/27/28, path traversal / SSRF / unsafe deserialize. Excludes the user already-reported list (1–46), withdrawn operator-equivalent candidates, and flagged JSON evidence sets.

## Candidates (MEDIUM+)

### 1. HIGH — Hetzner external CCM API token Secret templated without `no_log`

- **Primary file:** `roles/kubernetes-apps/external_cloud_controller/hcloud/tasks/main.yml`
- **Evidence:**
  - `roles/kubernetes-apps/external_cloud_controller/hcloud/tasks/main.yml:2-16` (templates `external-hcloud-cloud-secret.yml` into `/etc/kubernetes` and `register`s results; **no** `no_log`)
  - `roles/kubernetes-apps/external_cloud_controller/hcloud/templates/external-hcloud-cloud-secret.yml.j2:7-8` (`token: "{{ external_hcloud_cloud.hcloud_api_token | b64encode }}"`)
  - `inventory/sample/group_vars/all/hcloud.yml:2-3` (documented opt-in)
  - Contrast: vSphere CSI secret apply uses `no_log: "{{ not (unsafe_show_logs|bool) }}"` (`roles/kubernetes-apps/csi_driver/vsphere/tasks/main.yml:34,41`)
- **Default vs opt-in:** Opt-in when `cloud_provider=external` and `external_cloud_provider=hcloud` with `external_hcloud_cloud.hcloud_api_token` set.
- **Attack chain:** Operator enables the Hetzner external CCM and supplies the API token. The Generate Manifests task renders the Secret YAML (base64 token) and registers the result without `no_log`. Default Ansible/ARA/CI logging archives the token. An attacker with log/artifact access recovers `HCLOUD_TOKEN`, calls the Hetzner Cloud API as the cluster project, and destroys or re-provisions nodes — without needing the CCM pod compromise described in finding #30.
- **Why distinct:** Finding #30 is RBAC `cluster-admin` + `:latest` on the CCM SA/image. Finding #42 lists Azure Disk / Cinder / GCP PD / OCI / external OpenStack / UpCloud credential `no_log` gaps only — **not** Hetzner. This is a different secret (`hcloud_api_token`) on a different code path.
- **Remaining doubts:** Token defaults to `""`; impact requires the operator to set a real token (normal for any working Hetzner CCM deploy). Template module does not always echo file bodies in non-diff mode; severity still matches accepted finding #42 (UpCloud was template-only).

### 2. HIGH — External vSphere CPI password Secret templated without `no_log`

- **Primary file:** `roles/kubernetes-apps/external_cloud_controller/vsphere/tasks/main.yml`
- **Evidence:**
  - `roles/kubernetes-apps/external_cloud_controller/vsphere/tasks/main.yml:13-24` (templates `external-vsphere-cpi-cloud-config-secret.yml` with mode 0644; **no** `no_log`)
  - `roles/kubernetes-apps/external_cloud_controller/vsphere/templates/external-vsphere-cpi-cloud-config-secret.yml.j2:9-11` (plaintext `external_vsphere_password` in `stringData`)
  - Contrast (correct pattern on the CSI sibling): `roles/kubernetes-apps/csi_driver/vsphere/tasks/main.yml:30-41` redacts secret create/apply with `no_log`
- **Default vs opt-in:** Opt-in external vSphere CPI (`cloud_provider=external`, `external_cloud_provider=vsphere`); password from `VSPHERE_PASSWORD` / `external_vsphere_password`.
- **Attack chain:** Operator enables external vSphere CPI. Playbook templates the `cpi-global-secret` manifest containing the vCenter password without `no_log`. Ansible/ARA/CI logs retain the password. Attacker with log access authenticates to vCenter as the CPI account and controls VMs/disks for the cluster. Finding #42 treated vSphere CSI as the **fixed** pattern and did not cover this CPI task.
- **Why distinct:** Not in finding #42 evidence (CSI/CCM list explicitly omitted vSphere because CSI already had `no_log`). Finding #10 is insecure TLS to vCenter, not log leakage. Finding #5 covers world-readable on-disk Secret YAML class separately; this filing is the log channel (same framing as #42).
- **Remaining doubts:** Same env var (`VSPHERE_PASSWORD`) can also feed CSI; if an operator enables only CPI (no CSI), this is the sole leak path. Disk mode 0644 is finding #5 class and is **not** re-filed here.

### 3. MEDIUM — Cilium IPsec key Secret templated without `no_log`

- **Primary file:** `roles/network_plugin/cilium/tasks/install.yml`
- **Evidence:**
  - `roles/network_plugin/cilium/tasks/install.yml:44-63` (loop templates `cilium/secret.yml` when encryption enabled; **no** `no_log`)
  - `roles/network_plugin/cilium/templates/cilium/secret.yml.j2:3-4` (`keys: {{ cilium_ipsec_key }}`)
  - `docs/cilium.md:97-109` (documented hardening: set `cilium_encryption_enabled` + `cilium_ipsec_key`; “Kubespray handles secret creation”)
- **Default vs opt-in:** Opt-in. Defaults keep `cilium_encryption_enabled: false`; official Cilium encryption docs require the key variable.
- **Attack chain:** Operator follows `docs/cilium.md` and enables IPsec encryption with `cilium_ipsec_key`. The install task templates the `cilium-ipsec-keys` Secret into `/etc/kubernetes` without `no_log`. Ansible/ARA/CI logs retain the key. Attacker with log access decrypts Cilium IPsec overlay traffic (and can forge it), defeating the documented encryption control. Parallel to finding #43 (encrypt-at-rest key logging) but a **different** secret.
- **Why distinct:** Finding #43 is `kube_encrypt_token` / `secrets_encryption.yaml` only. CNI encryption-off alone was rejected; this is the logging gap on the documented enabled path.
- **Remaining doubts:** Opt-in only; WireGuard path does not template this Secret. On-disk mode 0644 is finding #5 class and is not re-filed.

## Checked surfaces — no additional MEDIUM+

- Flagged 1–46 / user already-reported list (including inventory_builder `shell=True`, recover `rm`, etcd/remove-node shells, world-readable `/etc/kubernetes` secrets, kubeadm/etcd/admin.conf `no_log`, CSI/CCM credential `no_log` set in #42, encrypt-at-rest `no_log` in #43, ArgoCD unsigned, Amazon EPEL HTTP GPG, Oracle extras `gpgcheck=0`, NVIDIA GTX HTTP, Heketi)
- Withdrawn / do-not-refile: FCOS/Debian `http_proxy` raw, Calico RR ids, make-ssl-etcd hostname assert, etcd 36500 alone, mitogen no checksum, Debian backports HTTP, zypper gpg-auto-import, kubeadm SAN shell (`ansible_fqdn`/DNS charset), Weave `EnterPasswordHere` overridden, kubeadm-upgrade local `validate_certs: false`, Vagrant/Docker/dind lab-only, registry empty htpasswd, containerd insecure opt-in, CI premoderator incomplete, additional `no_log` on same kubeadm/etcd/admin.conf as #6, 0644 Secret YAML disk class as #5
- **Shell injection:** Remaining unquoted shells (`etcd_access_address`, `etcd_member_name`, `node_ip`, `broken_etcd`) already in #17/#18. `apiserver_sans` host loop still lacks a complete non-operator metacharacter chain. `hostnamectl` / inventory hostname constrained by preinstall assert. Python `shell=True` only inventory_builder (#25). `library/kube.py` argv-safe. `contrib/inventory_builder` `yaml.load` is operator-controlled inventory file (no weaker attacker).
- **Unsigned privileged downloads:** ArgoCD (#19), Amazon EPEL GPG (#20), NVIDIA HTTP (#27), Oracle extras (#28), Heketi HTTP (#26) already flagged. cri-o HTTP repos appear on cleanup/reset only. Download role keeps sha256 for kube/CNI/runtime binaries. Mitogen HTTPS without checksum previously withdrawn as weak.
- **Other `no_log` looked at and not filed:** in-tree `cloud_config` template (`roles/kubernetes/node/tasks/main.yml:177-188`) embeds the **same** Azure/OpenStack/vSphere passwords already covered by #42’s secret class; canal etcd key `slurp` same class as #6; kubeadm join token leakage previously reported before #6; `kube_token_auth` defaults false; RHEL activation-key task lacks `no_log` but impact is RH entitlements not cluster/cloud takeover (below bar); MetalLB BGP `peer.password` opt-in ConfigMap — network peer secret only, weaker than CCM/CSI tokens.
- **SSRF / path traversal / deserialize:** Calico/node-label `uri` health checks hit cluster endpoints with client certs (not attacker URL). Download mirrors operator-configured. No new pickle/unsafe YAML load sinks with a weaker-than-operator attacker.
