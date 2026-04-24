# Frida-DAS: A FRI-based Data Availability Sampling Scheme in Go

This repository contains a Go implementation of the FRIDA protocol — a FRI-based Data Availability Sampling (DAS) scheme that enables blockchain light nodes to verify data availability without downloading entire blocks.

> Based on the paper: [FRIDA: Data Availability Sampling from FRI](https://eprint.iacr.org/2024/248)

## Project Structure

```
.
├── cmd/
│   ├── cli/        # User-facing CLI (commit, open, verify, simulate)
│   └── bench/      # Benchmarking binary with CSV output
├── pkg/
│   └── frida/      # Core protocol library (FRI, Merkle, NTT, folding)
├── sim/            # DAS network simulation (light nodes, honest/malicious providers)
└── Makefile
```

## Prerequisites

- Go 1.22+

## Building

```bash
make build
```
This produces two executable binaries, the `./frida-das` as the CLI program and the `./frida-bench` as the benchmark program.
## Testing

```bash
make test
```

## CLI Usage

```bash
./frida-das <command> [flags]
```

### Commands

| Command | Description |
|---|---|
| `generate-data` | Generate random test data |
| `commit` | Commit to a data file and print timing stats |
| `open` | Open a proof at specific domain positions |
| `verify` | Verify a commitment |
| `simulate` | Run a full DAS network simulation |

### Examples

```bash
# Generate 64KB of test data
./frida-das generate-data --size 65536 --out data.bin

# Commit using NTT evaluator with parallel-batch folding (default)
./frida-das commit --data data.bin --blowup 8 --folding 4 --remainder 31 --batch 64 --queries 32

# Open a proof at positions 0, 1, 5
./frida-das open --data data.bin --pos 0,1,5

# Verify the commitment
./frida-das verify --data data.bin

# Run a DAS simulation: 50 light nodes, 20 samples each, export JSON
./frida-das simulate --data data.bin --nodes 50 --samples 20 --out result.json

# Simulate with 90% data corruption
./frida-das simulate --data data.bin --nodes 50 --samples 20 --corrupt-fraction 0.9
```

### Evaluator & Folder Flags

`commit`, `open`, `verify`, and `simulate` all accept:

| Flag | Options | Default | Description |
|---|---|---|---|
| `--evaluator` | `hornor`, `ntt` | `ntt` | Polynomial evaluator for Reed-Solomon encoding |
| `--folder` | `serial-ordinary`, `serial-batch`, `parallel-batch` | `parallel-batch` | FRI folding strategy |

## Benchmarks

```bash
# Optimised (NTT + parallel-batch) > bench_results.csv
make bench

# Baseline (Horner + serial-ordinary) > bench_horner.csv
make bench-baseline

# Compare all three folding strategies side-by-side > three CSVs
make bench-compare

# Clean all CSV output
make clean
```

Or run directly with custom parameters:

```bash
./frida-bench \
    --fri-options "4,2,15;8,4,31"
    --data-sizes "256,1024,4096,16384,65536,131072,262144" \
    --batch-sizes "1" \
    --num-queries 32 \
    --evaluator ntt \
    --folder parallel-batch \
    --output ntt_scaling.csv
```

The CSV output is aligned with the [NethermindEth's Rust benchmark suite](https://github.com/NethermindEth/Frida-poc/tree/main/bench) format for direct comparison.

## Optimizations

| Optimization | Impact                            |
|---|-----------------------------------|
| NTT evaluator (O(n log n) vs Horner O(n²)) | ~??× erasure speedup on ???       |
| Montgomery batch inversion in barycentric interpolation | ~?× commitment speedup on ???     |
| Parallel algebraic hash across CPU cores | ~?× commitment speedup            |

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Acknowledgements

Based on the FRIDA paper. Reference Rust implementation by NethermindEth.
