import numpy as np
import pytest

from phish_triage.models.transformer import encode, pad


class FakeTokenizer:
    """One token per word, ids = word numbers; [CLS] = 101, [SEP] = 102 (as in BERT)."""

    cls_token_id, sep_token_id, pad_token_id = 101, 102, 0

    def __call__(self, texts, add_special_tokens, truncation):
        assert not add_special_tokens and not truncation
        return {"input_ids": [[int(w) for w in t.split()] for t in texts]}


TOKENIZER = FakeTokenizer()
LONG = " ".join(str(i) for i in range(1, 1001))  # 1,000 tokens


def test_head_keeps_the_start():
    ids = encode(TOKENIZER, [LONG], "head", max_tokens=12)[0]
    assert ids == [101, *range(1, 11), 102]


def test_head_tail_keeps_both_ends():
    ids = encode(TOKENIZER, [LONG], "head_tail", max_tokens=12)[0]
    assert ids == [101, 1, 2, 3, 4, 5, 996, 997, 998, 999, 1000, 102]


def test_short_emails_are_not_cut():
    assert encode(TOKENIZER, ["7 8 9"], "head_tail")[0] == [101, 7, 8, 9, 102]
    with pytest.raises(ValueError):
        encode(TOKENIZER, ["1"], "middle")


def test_pad_to_the_longest_in_the_batch():
    input_ids, mask = pad([[101, 5, 102], [101, 102]], pad_id=0)
    assert input_ids.tolist() == [[101, 5, 102], [101, 102, 0]]
    assert mask.tolist() == [[1, 1, 1], [1, 1, 0]] and input_ids.dtype == np.int64
