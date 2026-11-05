def test_masking_refuses_private_data_without_its_collection_names(monkeypatch):
    import pytest

    from phish_triage.data import mask

    monkeypatch.setattr(mask, "_COLLECTORS_MISSING", True)
    with pytest.raises(RuntimeError, match="collectors.json is missing"):
        mask.mask_record({"headers": [], "subject": "", "text": "", "html": "", "urls": [], "attachments": []})
