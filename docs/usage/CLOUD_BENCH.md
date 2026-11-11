# Try Quantum-Go on AWS or Google Cloud

`scripts/cloud-bench.sh` launches two small VMs, runs the same matrix we publish in [PERFORMANCE.md](../PERFORMANCE.md#between-two-cloud-hosts), prints a table and deletes everything. It takes about ten minutes and a few cents to a few dollars, depending on the instance type. Run it before you commit to a deeper evaluation: you get real two-host numbers for your own network, region and hardware.

## What you need

- A laptop or CI box with `bash`, `ssh`, `curl` and Go (the binary is built from your checkout, so the numbers describe the code you are reading).
- AWS: the `aws` CLI logged in, a default region, and a default VPC. Or Google Cloud: the `gcloud` CLI logged in, a project with billing already linked, a default zone, and the `default` network.

The script never creates a project, never links billing, and never opens a port wider than your own address.

## Run it

```sh
scripts/cloud-bench.sh aws            # dry run: checks everything and prints the plan, creates nothing
scripts/cloud-bench.sh aws --yes      # launch, run the matrix, tear down
scripts/cloud-bench.sh gcp --yes
```

Options: `--duration SECONDS` (default 10 per cell), `--instance-type TYPE`, `--cross-zone` (put the two VMs in different zones), `--out DIR` (default `./cloud-bench-results/<run id>`).

Defaults: AWS `c7i-flex.large` (free-plan eligible), Google Cloud `c3-standard-8`. On the AWS free plan the script refuses any other type and says why. On Google Cloud a family can have a zero quota in a region; the script tells you to pick another zone or type.

## What it does and what it costs

1. Checks credentials, region or project, network, instance type and plan, and prints the plan with the run time and the cost note. Without `--yes` it stops here.
2. Creates a throwaway key pair, a security group (AWS) or two firewall rules (Google Cloud), and two VMs, all tagged with one run id. SSH is allowed from your current public address only; the benchmark port is open only between the two VMs.
3. Builds `quantum-tunnel` for linux/amd64, copies it over, and runs 15 cells: plain TCP against the tunnel at 1400 B, 8 KB and 60 KB records with one and four flows, then the datagram transport at 1000 and 4000 Mbps offered and unpaced. Datagram cells raise `net.core.rmem_max` to 4 MiB on both VMs first; the output says so.
4. Deletes everything and checks by tag that nothing is left.

The cloud bills the two VMs for the run. The script does not print a dollar figure because prices differ by region and change; look up the hourly price of the instance type in your region. As a safety net the VMs shut themselves down after 90 minutes even if the script is killed.

## Results

`results.md` is a table (Gbps at the receiver, loss, CPU seconds per GiB on each side) with the provider, zone, instance type, commit and date. `raw.log` holds the raw bench output with addresses masked. Single 10 s runs are indicative, not medians; repeat for anything you plan to quote.

How to read them: plain TCP shows the link or per-flow limit. If one tunnel flow sits below plain TCP while four flows match it, one core is the limit, not the network. Datagram loss is measured by sequence number at the receiver.

## If something goes wrong

- **The script died or you pressed Ctrl-C:** a trap deletes the run's resources. If it warns that something may remain, sweep by tag: `scripts/cloud-bench.sh aws cleanup --yes` (or `gcp`). It deletes every resource tagged `quantum-go-bench` in the current region or project.
- **SSH drops mid-run:** a VPN reconnect changes your public address and the security rule no longer matches. The run aborts and teardown still runs. Turn the VPN off for the run, or run from a machine with a stable address.
- **AWS `InvalidParameterCombination`:** the free plan only allows free-tier-eligible types.
- **Google Cloud quota error:** try another zone with `GCP_ZONE=<zone>`, or `--instance-type n2-standard-8`.
- **Corporate accounts:** if your organization enforces OS Login on Google Cloud, instance-metadata SSH keys do not work; use a project without that policy.
