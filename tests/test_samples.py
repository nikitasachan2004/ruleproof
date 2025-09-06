"""Unit tests for sample indexing and ground-truth technique mapping."""

from pathlib import Path

from ruleproof.samples import index_samples, parse_mapping_csv


def test_parse_mapping_csv() -> None:
    csv_path = Path(__file__).parent / "fixtures" / "samples" / "sample_mapping.csv"
    mapping = parse_mapping_csv(csv_path)

    assert "CA_Mimikatz.evtx" in mapping
    assert mapping["CA_Mimikatz.evtx"] == ["T1003.001"]

    assert "pcalua.evtx" in mapping
    assert mapping["pcalua.evtx"] == ["T1218"]


def test_index_samples_ground_truth_policy() -> None:
    samples_dir = Path(__file__).parent / "fixtures" / "samples"
    csv_path = samples_dir / "sample_mapping.csv"

    records = index_samples(samples_dir, mapping_csv=csv_path, dataset_commit="test_commit")
    records_by_id = {r.sample_id: r for r in records}

    # Labelled sample
    assert "CA_Mimikatz.evtx" in records_by_id
    mimikatz_rec = records_by_id["CA_Mimikatz.evtx"]
    assert mimikatz_rec.is_labelled is True
    assert mimikatz_rec.techniques == ["T1003.001"]
    assert "test_commit" in mimikatz_rec.label_source

    # Unlabelled sample (not in CSV)
    assert "unlabelled_noise.evtx" in records_by_id
    unlabelled_rec = records_by_id["unlabelled_noise.evtx"]
    assert unlabelled_rec.is_labelled is False
    assert unlabelled_rec.techniques == []
    assert "unlabelled:no_author_mapping" in unlabelled_rec.label_source
