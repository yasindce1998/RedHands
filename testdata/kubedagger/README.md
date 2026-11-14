# KubeDagger fixtures

Used by the golden pipeline tests in `tools/kubedagger/k8s_discover_golden_test.go`
and `internal/app/recorder_golden_test.go` (full
fixture → wrapper → campaign extraction → record rules → targetdb flow).

## Provenance

- `client-help.txt` — **real run**: `kubedagger-client --help` (built from the
  KubeDagger repository with `go build ./cmd/kubedagger-client`). Capture with:

  ```bash
  go build -o kubedagger-client ./cmd/kubedagger-client
  ./kubedagger-client --help > client-help.txt
  ```

- `k8s-discover-no-kubeconfig.stderr` — **real run** of
  `kubedagger-client k8s discover --namespace default` on a machine with no
  kubeconfig and no live daemon: the real failure shape the wrapper must
  surface. Capture with:

  ```bash
  ./kubedagger-client k8s discover --namespace default 2> k8s-discover-no-kubeconfig.stderr
  ```

  Note the quirk verified against the real binary: on this failure the
  process **exits 0**, stdout is **empty**, and the `Error: k8s client init
  failed: ...` text plus usage goes to **stderr**. The `kubedagger_k8s_discover`
  wrapper therefore treats empty stdout + non-empty stderr as a failure and
  surfaces the stderr text as an error result (empty stdout + empty stderr
  remains a successful "No resources found." result) — asserted by the golden
  test in `tools/kubedagger/k8s_discover_golden_test.go`.

- `cluster-report.json` — **struct-derived** (documented): `k8s discover`
  needs a live daemon plus a Kubernetes client, so this file was hand-crafted
  strictly against the `ClusterReport` struct the command prints
  (`cmd/kubedagger-client/run/k8s/discovery.go`):

  ```go
  type ClusterReport struct {
      Nodes      []NodeInfo     `json:"nodes"`      // {name, ip, os, kernel, kubelet, conditions}
      Pods       []PodInfo      `json:"pods"`       // {name, namespace, node_name, pod_ip, image, privileged, host_pid, host_network}
      Services   []ServiceInfo  `json:"services"`   // {name, namespace, type, cluster_ip, ports}
      Namespaces []string       `json:"namespaces"`
      Targets    []AttackTarget `json:"targets"`    // {name, type, reason}
  }
  ```

  The command ends with `json.MarshalIndent(report, "", "  ")` +
  `fmt.Println(string(data))`, so the successful stdout of
  `kubedagger-client k8s discover` is exactly this pretty-printed JSON object
  (no wrapper headers, no trailing decoration). The field names here are what
  the `k8s-recon-chain` playbook record rules depend on (`nodes[].ip`,
  `nodes[].name`, `nodes[].os`, `pods[].pod_ip`, `pods[].name`).
