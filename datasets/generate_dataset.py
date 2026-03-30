"""
Dataset generation script.

Generates a synthetic training dataset and optionally downloads
public vulnerability datasets (Big-Vul, Devign) for model training.

Usage:
    python datasets/generate_dataset.py --synthetic
    python datasets/generate_dataset.py --download  # requires internet
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parents[1]))

from vulnscanner.ml.trainer import generate_synthetic_dataset
from vulnscanner.utils.logging import get_logger

logger = get_logger("dataset_gen")


def generate_synthetic(output: Path) -> None:
    df = generate_synthetic_dataset(output)
    print(f"Generated {len(df)} synthetic samples → {output}")
    print(f"Class distribution:\n{df['label'].value_counts().to_string()}")


def download_bigvul(output_dir: Path) -> None:
    """
    Download and preprocess the Big-Vul dataset.
    Source: https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset
    """
    import urllib.request
    import pandas as pd

    url = "https://raw.githubusercontent.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset/master/all_c_cpp_release2.0.csv"
    raw_path = output_dir / "bigvul_raw.csv"

    logger.info(f"Downloading Big-Vul dataset from {url}")
    urllib.request.urlretrieve(url, raw_path)

    df = pd.read_csv(raw_path, low_memory=False)
    logger.info(f"Raw Big-Vul: {len(df)} rows, columns: {list(df.columns[:10])}")

    # Extract relevant columns
    if "func_before" in df.columns and "vul" in df.columns:
        processed = df[["func_before", "vul"]].rename(
            columns={"func_before": "code_snippet", "vul": "label"}
        )
        processed["language"] = "c"
        processed = processed.dropna(subset=["code_snippet"])
        processed = processed.sample(min(5000, len(processed)), random_state=42)

        out_path = output_dir / "bigvul_processed.csv"
        processed.to_csv(out_path, index=False)
        logger.info(f"Processed Big-Vul: {len(processed)} samples → {out_path}")
    else:
        logger.warning("Unexpected Big-Vul schema — check column names")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScanner AI dataset generator")
    parser.add_argument("--synthetic", action="store_true", help="Generate synthetic dataset")
    parser.add_argument("--download", action="store_true", help="Download Big-Vul dataset")
    parser.add_argument("--output-dir", default="datasets", help="Output directory")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.synthetic or not args.download:
        generate_synthetic(output_dir / "synthetic_training.csv")

    if args.download:
        try:
            download_bigvul(output_dir)
        except Exception as e:
            logger.error(f"Download failed: {e}")
            logger.info("Falling back to synthetic dataset only")
            generate_synthetic(output_dir / "synthetic_training.csv")
