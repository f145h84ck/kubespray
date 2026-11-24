# Security research findings (2026-11-24) — injection / crypto / secrets

Commit reviewed: `1e7f003be52994a3c709d8c5d658e0b7042c7155`. Scope: remaining shell/raw injection of inventory/cloud-derived fields, get_url checksum gaps, hardcoded secrets, remaining `no_log` on secret copy/template/slurp, encryptionconfig, kubeconfig_localhost, contrib/offline, `library/*.py`, `scripts/*.sh`, download checksums, containerd, CI secret exposure. Excludes the user already-reported list, withdrawn operator-equivalent candidates, and flagged JSON findings 1–41 evidence sets.

## Candidates (MEDIUM+)

### 1. HIGH — Cloud CSI/CCM credential slurp / set_fact / template tasks lack `no_log`

- **Primary file:** `roles/kubernetes-apps/csi_driver/azuredisk/tasks/main.yml`
- **Evidence:**
  - `roles/kubernetes-apps/csi_driver/azuredisk/tasks/main.yml:12-31` (slurp + Secret template; config embeds `aadClientSecret` in `azure-csi-cloud-config.j2:5`)
  - `roles/kubernetes-apps/csi_driver/cinder/tasks/main.yml:23-36`
  - `roles/kubernetes-apps/csi_driver/gcp_pd/tasks/main.yml:15-30`
  - `roles/kubernetes-apps/cloud_controller/oci/tasks/main.yml:12-26` (slurp/set_fact of config embedding `oci_private_key`)
  - `roles/kubernetes-apps/external_cloud_controller/openstack/tasks/main.yml:15-18` (`set_fact` of base64 cloud-config with `password=` / application-credential-secret)
  - `roles/kubernetes-apps/csi_driver/upcloud/tasks/main.yml:15-21` + `upcloud-csi-cred-secret.yml.j2:8-9` (plaintext password in templated Secret YAML)
  - Contrast (correct pattern): `roles/kubernetes-apps/csi_driver/vsphere/tasks/main.yml:34,41` already uses `no_log: "{{ not (unsafe_show_logs|bool) }}"`
- **Default vs opt-in:** Opt-in per cloud (`azure_csi_enabled`, `cinder_csi_enabled`, `gcp_pd_csi_enabled`, OCI/external OpenStack/UpCloud CCM/CSI). Documented sample inventory paths.
- **Attack chain:** Operator enables one of the CSI/CCM integrations above. Playbooks `slurp` or `set_fact` the cloud credential material, then `template` Secret manifests, all without `no_log`. Default Ansible/ARA/CI logging archives the base64 (or plaintext) Azure client secret, OpenStack password, GCP SA JSON, OCI private key, or UpCloud password. An attacker with access to those logs recovers long-lived cloud credentials and takes over volumes/LBs/instances — without needing SSH or local Unix read of `/etc/kubernetes`. Finding #5 covers world-readable on-disk Secret YAML for some of these; this is the separate log/artifact channel. Finding #6 evidenced only kubeadm certificate-key / etcd CA / admin.conf, not these CSI/CCM tasks.
- **Why distinct:** Not in flagged JSON evidence. Sibling vSphere CSI tasks already redact with `no_log`, showing the intended pattern was known but not applied here.

### 2. MEDIUM — `kube_encrypt_secret_data` encryption-key slurp / set_fact / template lack `no_log`

- **Primary file:** `roles/kubernetes/control-plane/tasks/encrypt-at-rest.yml`
- **Evidence:** `roles/kubernetes/control-plane/tasks/encrypt-at-rest.yml:10-40`, `roles/kubernetes/control-plane/templates/secrets_encryption.yaml.j2:10`, `docs/hardening.md:39-40` / `docs/hardening.md:120`
- **Default vs opt-in:** Opt-in. Official hardening guide sets `kube_encrypt_secret_data: true`. File mode is 0640 (already checked previously); logging is the gap.
- **Attack chain:** Operator follows `docs/hardening.md` and enables secret encryption at rest. On first apply (or when re-reading an existing `secrets_encryption.yaml`), the role `slurp`s the EncryptionConfiguration, `set_fact`s `kube_encrypt_token_extracted` / `kube_encrypt_token`, and `template`s the key file — none of those tasks set `no_log`. Ansible/ARA/CI logs retain the provider key. An attacker with log access plus any etcd snapshot/backup (common ops artifact) decrypts all Secrets, defeating the hardening control. Distinct from finding #6 evidence (certificate-key / etcd CA / admin.conf).
- **Why distinct:** Prior hunts only verified file mode 0640 for encrypt-at-rest; they did not file the missing `no_log` on the documented hardening path.

## Checked surfaces — no additional MEDIUM+

- Already-reported / flagged 1–41 and user list (inventory_builder `shell=True`, recover-control-plane `rm`, etcd/remove-node `access_ip`/`etcd_member_name` shells, world-readable `/etc/kubernetes` cloud Secret YAML, no_log on certificate-key/etcd CA/admin.conf, ArgoCD unsigned downloads, Amazon EPEL HTTP GPG, Oracle extras `gpgcheck=0`, NVIDIA GTX HTTP, Heketi, vSphere TLS/terraform `allow_unverified_ssl`, `host_key_checking=False`, `unsafeSkipCAVerification`, dual-stack nginx `[::]` bind)
- Withdrawn / do-not-refile: FCOS/Debian `http_proxy` raw (operator extra-vars), Calico RR id shell (operator inventory labels), make-ssl-etcd hostname (hostname assert), etcd `certificates_duration` alone, mitogen HTTPS no checksum, Debian 10 HTTP backports, zypper `--gpg-auto-import-keys`
- **Shell injection remaining:** `kubeadm-setup` SAN check joins `apiserver_hosts` (includes `ansible_fqdn` / non-IP `access_ip`) into an unquoted `for HOST in ...` shell, but only when kubeadm already ran. Valid DNS labels / terraform `access_ip` values lack shell metacharacters; hostname assert covers `inventory_hostname`. No complete non-operator chain.
- **Weave `EnterPasswordHere`:** `kubespray-defaults` still defines it, but weave role defaults (`~`) load later and win (verified with Ansible role-default precedence). Enabling weave without a password disables encryption. Docs example password is a footgun if copy-pasted into inventory, not a live default.
- **kubeconfig_localhost:** artifacts dir 0750, `admin.conf` mode 0600; slurp of admin.conf already in finding #6
- **Download role:** kube/CNI/containerd/cri-o/runc/crictl/etcd binaries keep sha256; `download_validate_certs: true`. Remaining `get_url` without checksum: ArgoCD (flagged), mitogen (withdrawn weak), Oracle yum repo file (HTTPS), tests/CI only
- **containerd:** `insecure_skip_verify` only when operator sets `containerd_insecure_registries`; no world-writable CRI socket default found
- **library/kube.py:** argv-safe `run_command` only; sole `shell=True` remains inventory_builder (flagged)
- **scripts/*.sh:** `premoderator.sh` puts `GITHUB_TOKEN` in query string but job is disabled (`only: []`); hash helpers use HTTPS
- **contrib/offline:** unauth registry already flagged; helper nginx on `:8080` serves public binary lists with autoindex — low incremental impact while download checksums still apply
- **registry empty htpasswd:** ClusterIP default, addon off
- **encryption off by default:** no new theft path beyond known host/etcd access
- **UpCloud/RBD/CephFS Secret YAML mode 0644:** same on-disk class as finding #5 (not re-filed as separate); UpCloud included above for the log/`no_log` channel
