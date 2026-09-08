#!/usr/bin/env bash
set -euo pipefail

printf 'authzperf: rust=' 
rustc +1.98.1 --version
printf 'authzperf: os=' 
uname -srmo
printf 'authzperf: logical_cpus=' 
getconf _NPROCESSORS_ONLN
printf 'authzperf: memory_kib=' 
awk '/^MemTotal:/ {print $2}' /proc/meminfo
printf 'authzperf: cpu_model=' 
LC_ALL=C lscpu | awk -F: '/^Model name:/ {sub(/^[[:space:]]+/, "", $2); print $2; exit}'

cargo +1.98.1 test --locked --release --test performance -- --ignored --nocapture --test-threads=1
