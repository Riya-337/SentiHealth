#!/usr/bin/env bash
# Download the public datasets used in evaluation/ (not redistributed with this repository; check each
# dataset's own page for its licence and citation).
#
#   WUSTL-EHMS-2020   https://research.engineering.wustl.edu/~jain/ehms/   (~4 MB)
#   CERT Insider Threat Test Dataset r4.2   CMU SEI, DOI 10.1184/R1/12841247   (4.8 GB archive;
#       ml/datasets/cert_r42.py extract keeps ~3 GB and the archive can then be deleted)
#
# Usage: bash scripts/fetch_datasets.sh [wustl|cert|all]
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
D="$HERE/data/external"
mkdir -p "$D"
what="${1:-all}"

if [[ "$what" == wustl || "$what" == all ]]; then
  curl -fsSL -o "$D/wustl-ehms-2020.csv" "https://research.engineering.wustl.edu/~jain/ehms/ftp/wustl-ehms-2020_with_attacks_categories.csv"
  echo "WUSTL-EHMS -> $D/wustl-ehms-2020.csv"
fi

if [[ "$what" == cert || "$what" == all ]]; then
  curl -fsSL -o "$D/answers.tar.bz2" https://ndownloader.figshare.com/files/24857828
  mkdir -p "$D/cert" && tar -xjf "$D/answers.tar.bz2" -C "$D/cert"
  if [[ ! -f "$D/r4.2.tar.bz2" ]]; then
    curl -fL --retry 3 -o "$D/r4.2.tar.bz2" https://ndownloader.figshare.com/files/24856766
  fi
  echo "586446b00e83ce5cdabf9dc889b0b6e7a9f44556cee3c03d39445d790122556c  $D/r4.2.tar.bz2" | shasum -a 256 -c
  echo "CERT r4.2 -> $D/r4.2.tar.bz2 ; next: python3 ml/datasets/cert_r42.py all"
fi
