# Local data and model setup

Place trusted artifacts from your original project copy in the paths below.
The dashboard API needs these five files before it can load the main detectors:

- models/random_forest_binary_cicids2017.pkl
- models/random_forest_multiclass_cicids2017.pkl
- models/xgboost_binary_cicids2017.ubj
- models/xgboost_multiclass_cicids2017.ubj
- models/multiclass_label_encoder.pkl

For the optional rare-family detectors, restore models/rare_infiltration.pkl
and models/rare_heartbleed.pkl. Use the dependency versions in requirements.txt
and only load model artifacts you trust.

For the bundled demonstration, restore data/processed/end_to_end_sample.parquet
from the original project or packaged demo. For dataset-backed experiments, use
the data paths in REPRODUCE.md and the relevant experiment scripts. Obtain
the benchmarks from their original providers and keep the raw files local.
Some tests import the inference backend and require the same detector artifacts.

The main README also describes the packaged release. Any reference to a bundled
sample in that release assumes the local sample has been restored.
