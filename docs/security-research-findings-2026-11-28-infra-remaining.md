# Security research findings (2026-11-28) — remaining infra / IAM / defaults

Commit reviewed: `dcc882113bcf4016228832852d76777572a34727`. Scope: remaining terraform/IAM/SG beyond flagged 1–46, azurerm leftovers, download checksum gaps for core kube/etcd/cni/runtime, containerd/cri-o/docker insecure-registry defaults, kube-proxy metrics bind, nginx/haproxy localhost proxies besides dual-stack `[::]`, Dockerfile runner path, `.github`/GitLab CI secret chains, inventory/sample security defaults, facts.yml / reset.yml / scale.yml. Excludes already-flagged 1–46 and the already-rejected list in the hunt prompt.

## Candidates (MEDIUM+)

None. No new HIGH/MEDIUM/CRITICAL with a complete internet, cloud-neighbor, or CI attacker chain distinct from the active flagged set.

## Checked surfaces — no additional MEDIUM+

- **Providers:** no `contrib/terraform/azure`, nifcloud, or opennebula in tree. Metal terraform is `contrib/terraform/metal` (packet-* is CI/test only).
- **azurerm:** Internet SSH/API and public LB already finding #3; `admin_password: changeme` inert under `disablePasswordAuthentication: true`; storage has no public container ACL primitive.
- **AWS:** VPC SG SSH world + VPC-all (#35); internet NLB (#4); IMDSv1 (#9); control-plane and worker IAM wildcards (#35/#44); `contrib/aws_iam` mirrors those; no userdata secrets; no S3/KMS resources created; EBS encryption unset incomplete under account defaults.
- **GCP:** cloud-platform scopes (#2); ingress world default (#14); sample ssh/api/nodeport use restricted IPs; firewalls without target_tags incomplete without world whitelist; no extra IAM beyond empty SA → default Compute SA.
- **OpenStack:** bastion/API world (#34); NodePorts (#12); `port_security_enabled` default true; extra SGs empty; etcd/gfs no FIP.
- **Hetzner / Exoscale / UpCloud / Metal / vSphere:** covered by #13, #36–41, #45–46; UpCloud sample 0.0.0.0–255 allowlists only matter if firewall enabled.
- **inventory/sample:** anonymous API / encrypt-off / PSA off expected; healthcheck port 8081 → nginx stub_status = info disclosure only.
- **containerd / cri-o / docker:** insecure registry lists default empty; `insecure_skip_verify` only when operator configures insecure registries; no insecure live-restore default; kube-proxy metrics bind `127.0.0.1:10249`.
- **nginx / haproxy:** API on `127.0.0.1` (dual-stack `[::]` is #16); healthcheck/`stub_status` and `check-ssl verify none` remain info-only / node-local.
- **download:** real sha256 for default amd64/arm64 kube/etcd/cni/containerd/runc; stub checksum `0` is unsupported-arch placeholder only; container image digests intentionally unset (HTTPS registry; no TLS-break chain).
- **Dockerfile:** kubectl without checksum in CI/runner image only (not production cluster path).
- **CI:** no `.github/workflows`; GitLab premoderator token-in-query and cloud_playbooks public networking remain CI-only / incomplete log-exfil.
- **facts.yml / reset.yml / scale.yml:** facts gather only; reset gated by confirmation; scale `upload-certs` without `no_log` is finding #6 class.
- **registry addon:** disabled by default, ClusterIP, empty htpasswd — incomplete without operator enable+expose (offline unauth registry remains #15).
- **dind / Vagrant:** lab-only privileged/NOPASSWD/insecure-key paths excluded.
- **scheduler/controller bind `0.0.0.0`:** CIS prefers localhost; secure ports still auth-gated — incomplete alone.
