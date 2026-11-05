import numpy as np

from phish_triage.evaluation import explanations as ex


def test_words_match_without_case_or_punctuation_and_every_copy_goes():
    text = "Verify your ACCOUNT now. Your account, verify!"
    assert ex.words_of(text) == ["verify", "your", "account", "now"]
    assert ex.remove(text, {"account", "verify"}).split() == ["your", "now.", "Your"]


def test_deletion_compares_the_explanation_with_random_words():
    # a toy scorer: the score is the share of "urgent" among the words
    score = lambda texts: np.array([t.split().count("urgent") / max(len(t.split()), 1) for t in texts])  # noqa: E731
    texts = ["urgent urgent please read the note"] * 4
    ranked = [["urgent", "please"]] * 4
    pools = [ex.words_of(t) for t in texts]
    r = ex.deletion(score, texts, ranked, pools, threshold=0.0)
    assert r["1"]["explanation_drop"] > r["1"]["random_drop"] and r["1"]["explanation_below"] == 1.0
    assert set(r) == {str(k) for k in ex.KS}


class FakeTokenizer:
    cls_token_id, sep_token_id, pad_token_id = 101, 102, 0

    def __call__(self, text, add_special_tokens=False, truncation=False, return_offsets_mapping=False):
        # one token per 3 characters of each word, like word pieces
        ids, offsets = [], []
        for m in ex._TOKEN.finditer(text):
            for start in range(m.start(), m.end(), 3):
                ids.append(len(ids) + 1000)
                offsets.append((start, min(start + 3, m.end())))
        return {"input_ids": ids, "offset_mapping": offsets}


def test_tokens_map_to_the_word_they_fall_in_and_the_window_is_cut():
    ids, owner = ex.window_words(FakeTokenizer(), "password reset now")
    assert ids[0] == 101 and ids[-1] == 102 and owner[0] is None and owner[-1] is None
    assert owner[1:-1] == [0, 0, 0, 1, 1, 2]
    ids, owner = ex.window_words(FakeTokenizer(), "password reset now", budget=4)
    assert len(ids) == 6 and owner[1:-1] == [0, 0, 0, 1]
