# Security research findings (2026-11-28) — injection / crypto / secrets / downloads

Commit reviewed: `dcc882113bcf4016228832852d76777572a34727` (pre-fix). Scope: `roles/download`, `roles/container-engine`, `roles/bootstrap-os`, `roles/network_plugin` (non-rejected CNIs), `extra_playbooks`, `library/`, `contrib/network-storage` (besides Heketi StorageClass), `contrib/kvm-setup`, `scripts/`, Jinja `|safe` / unquoted shell sinks with inventory hostname/IP/filename attacker model. Excludes flagged 1–46 and the user already-rejected list.

## New MEDIUM+ (finding #47)

### 1. HIGH — CRI-O registry auth file written world-readable under `/etc/crio`

- **Primary file:** `roles/container-engine/cri-o/tasks/main.yaml`
- **Evidence (pre-fix):**
  - `roles/container-engine/cri-o/tasks/main.yaml:51-59` creates `/etc/crio` mode `0755`
  - `roles/container-engine/cri-o/tasks/main.yaml:68-73` templates `config.json` mode `0644`
  - `roles/container-engine/cri-o/templates/config.json.j2:1-14` embeds `b64encode(username:password)` when `crio_registry_auth` is set
  - `roles/container-engine/cri-o/templates/crio.conf.j2:317` sets `global_auth_file = "/etc/crio/config.json"`
  - `inventory/sample/group_vars/all/cri-o.yml:3-6` documents the auth shape
  - Contrast: containerd writes registry passwords into `config.toml` at mode **`0640`** (`roles/container-engine/containerd/tasks/main.yml:106-111`)
- **Default vs opt-in:** Requires `container_manager: crio` (documented in `docs/cri-o.md`) **and** non-empty `crio_registry_auth` (sample inventory). Common for private/offline registries.
- **Attack chain:**
  1. Operator deploys with CRI-O and configures `crio_registry_auth` for a private registry (often the same registry that hosts pause/control-plane images).
  2. Playbook writes `/etc/crio/config.json` mode `0644` on a `0755` directory on every node.
  3. Unprivileged local Unix user reads the file and base64-decodes the auth blob.
  4. Stolen credentials pull (and, if push-capable, overwrite) cluster images → node root / cluster takeover on next pull or restart.
- **Why distinct from 1–46:** Finding #5 covers world-readable cloud/vSphere Secret YAML under `/etc/kubernetes` only. This is a different path (`/etc/crio/config.json`) and a different secret class (registry pull/push credentials). Not a `no_log`-only / template-log class (#6/#42/#43). cri-o HTTP `crio_download_base` was previously rejected as cleanup-only and is unrelated.
- **Remediation applied in this change:** set `config.json` mode to `0600` and add `no_log` gated by `unsafe_show_logs`.

## Checked surfaces — no additional MEDIUM+

- Flagged 1–46 / user already-reported and already-rejected lists (including FCOS/Debian proxy raw, Calico RR ids, make-ssl-etcd hostname assert, canal etcd slurp, cri-o HTTP cleanup, in-tree cloud_config 0640, `/tmp/releases` TOCTOU, Hetzner CCM / vSphere CPI / Cilium IPsec template-only `no_log`)
- **Shell/command injection:** Remaining unquoted `access_ip` / `etcd_member_name` / `broken_etcd` sinks already #17/#18. Hostname constrained by preinstall DNS assert. `hostnamectl` uses `command` (argv). Calico RR / `calico_group_id` shells are operator group_vars (withdrawn class). `library/kube.py` argv-safe. `contrib/inventory_builder` `shell=True` is #25. No new cross-node hostname/IP injection with a complete lower-trust inventory contributor chain.
- **Downloads / package trust:** Core binary downloads keep sha256 + `download_validate_certs: true`. ArgoCD/EPEL/NVIDIA/Oracle/Heketi already flagged. Mitogen HTTPS without checksum previously withdrawn as weak. Flatcar/CoreOS `bootstrap.sh` verifies PyPy sha256 over HTTPS. skopeo URL is third-party but checksummed.
- **Network plugins:** Cilium kvstore hard-links etcd keys at 0644 under **0750** `/etc/cilium/certs` (directory blocks others; calico sibling correctly uses 0640). Typha/apiserver cert dirs 0755 are opt-in off-by-default; OpenSSL private keys typically 0600. Weave password Secret under `/etc/kubernetes` is #5 on-disk class when set. Flannel/kube-router/kube-ovn/macvlan/ovn4nfv: no new MEDIUM+ injection or world-readable secret chain.
- **bootstrap-os:** Amazon EPEL HTTP GPG #20; Oracle extras `gpgcheck=0` #28. Remaining distros: no new HTTP+gpgcheck=0 privileged default. FCOS/Debian `http_proxy` raw withdrawn.
- **contrib:** `kvm-setup` SSH key mode 0400; heketi StorageClass HTTP key #26; heketi.json 0644 under `/etc/kubernetes` is #5 class; glusterfs bootstrap mirrors Amazon/Oracle issues already flagged.
- **scripts / tests:** `premoderator` token-in-query incomplete CI hygiene; `yaml.load` on operator-local files; no production-role test fixtures introducing new sinks.
- **SSRF / `|safe` / deserialize:** No Jinja `|safe` sinks. Health-check `uri` calls hit cluster endpoints with client certs, not attacker URLs. No new pickle/unsafe YAML attacker-controlled loaders.
