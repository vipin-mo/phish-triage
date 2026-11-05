import math

import numpy as np

from phish_triage.data import time_split
from phish_triage.evaluation import sender_ablation
from phish_triage.features.extract import FEATURE_NAMES, HEADER_FEATURES
from phish_triage.service import bundle


def test_phishing_after_the_cut_never_trains_and_is_tested():
    base = {"train": ["old", "new", "legit"], "val": ["new_val", "legit_val"], "test": ["test_old", "test_new", "l"]}
    month = {"old": "2026-03", "new": "2026-08", "new_val": "2026-10", "test_old": "2026-07", "test_new": "2026-09"}
    split, slices = time_split.build_split(base, ["test_old", "test_new"], month)
    assert split["train"] == ["old", "legit"]
    assert split["val"] == ["legit_val"]
    assert sorted(split["test"]) == ["l", "new", "new_val", "test_new", "test_old"]
    assert slices["phish_before_cut"] == ["test_old"]
    assert slices["phish_after_cut"] == ["new", "new_val", "test_new"]
    assert not set(slices["phish_after_cut"]) & set(split["train"] + split["val"])


def test_time_split_reads_like_the_deployed_split():
    assert bundle.reader_of(time_split.SPLIT) == 2
    assert bundle.split_of_version("with-time-split-20261105-ab12cd34") == time_split.SPLIT


def test_ablation_blanks_only_the_named_columns():
    rows = np.ones((3, len(FEATURE_NAMES)))
    out = sender_ablation.blank(rows, sender_ablation.AUTH)
    blanked = [FEATURE_NAMES[k] for k in range(len(FEATURE_NAMES)) if math.isnan(out[0, k])]
    assert blanked == ["dkim_signed", "dkim_aligned"]
    assert rows[0, FEATURE_NAMES.index("dkim_signed")] == 1  # the input is unchanged
    assert set(sender_ablation.left_out("no_header")) == set(HEADER_FEATURES)
    assert sender_ablation.left_out("all") == ()
