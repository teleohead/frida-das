.PHONY: build test bench bench-baseline bench-compare clean

# BUILD BINARIES
build:
	go build ./...

# RUN ALL TESTS
test:
	go test ./...

# BENCHMARK WITH NTT EVALUATOR + PARALLELIZED BATCH (MONTGOMERY's) FOLDING
bench:
	go run ./cmd/bench/ \
		--evaluator ntt \
		--folder parallel-batch \
		--output bench_results.csv

# BENCHMARK WITH HORNER's EVALUATOR + ORDINARY SERIAL FOLDING (THIS IS REALLY SLOW BTW)
bench-baseline:
	go run ./cmd/bench/ \
		--evaluator horner \
		--folder serial-ordinary \
		--output bench_horner.csv

# BENCHMARK WITH NTT EVALUATOR + THREE DIFFERENT FOLDING STRATEGIES
bench-compare:
	go run ./cmd/bench/ --evaluator ntt --folder serial-ordinary --output bench_serial_ordinary.csv
	go run ./cmd/bench/ --evaluator ntt --folder serial-batch    --output bench_serial_batch.csv
	go run ./cmd/bench/ --evaluator ntt --folder parallel-batch  --output bench_parallel_batch.csv

clean:
	rm -f bench_*.csv
