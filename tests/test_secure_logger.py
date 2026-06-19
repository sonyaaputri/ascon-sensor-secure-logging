from src.ascon import ASCON_128A_IV, ASCON_HASH_IV, ascon_hash256
from src.dataset import generate_sensor_records
from src.secure_logger import (
    decrypt_all_records,
    secure_log_records,
    tamper_ciphertext,
    tamper_delete_last_record,
    tamper_delete_record,
    tamper_device_id,
    tamper_insert_duplicate_record,
    tamper_swap_order,
    tamper_tag,
    tamper_timestamp,
    verify_full_log,
)


def test_ascon_sp800_232_initial_values():
    assert ASCON_128A_IV == 0x00001000808C0001
    assert ASCON_HASH_IV == 0x0000080100CC0002


def test_ascon_hash256_matches_byte_aligned_acvp_vectors():
    vectors = {
        b"": "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2",
        bytes.fromhex("0A"): "56AA2B055CA35C13960CC12FE4DA2AA1034B0218CEF0FF66DF4FC883610613E8",
        bytes.fromhex("DC7E"): "D9AFF24FA30D3778562A97D8CEA71B8E0703097AC405C4C3AC07096244F04C42",
        bytes.fromhex("0E9F50FE"): "621DCC0760FD204E539D35686509246B89D0E7F74AF89BF22DF07B737719A470",
        bytes.fromhex("04EAA8B0020CCE53"): "91C8753C2C185F78643AC2F6757FA8D7BC2DDDA8C4585A487A7C1DFE39BE879C",
    }
    for message, expected in vectors.items():
        assert ascon_hash256(message).hex().upper() == expected


def test_normal_log_is_valid_and_decrypts_to_original_records():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(secure_records, anchor)
    assert report.ok
    assert decrypt_all_records(secure_records) == records


def test_derived_nonces_are_unique_within_log():
    records = generate_sensor_records(20)
    secure_records, _ = secure_log_records(records)
    nonces = [record["nonce"] for record in secure_records]
    assert len(nonces) == len(set(nonces))


def test_ciphertext_tamper_is_detected():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(tamper_ciphertext(secure_records), anchor)
    assert not report.ok
    assert report.detected_by_aead
    assert report.detected_by_hash_chain


def test_authentication_tag_tamper_is_detected():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(tamper_tag(secure_records), anchor)
    assert not report.ok
    assert report.detected_by_aead
    assert report.detected_by_hash_chain


def test_metadata_tamper_is_detected_by_aead_and_hash_chain():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)

    timestamp_report = verify_full_log(tamper_timestamp(secure_records), anchor)
    device_report = verify_full_log(tamper_device_id(secure_records), anchor)

    assert not timestamp_report.ok
    assert timestamp_report.detected_by_aead
    assert timestamp_report.detected_by_hash_chain
    assert not device_report.ok
    assert device_report.detected_by_aead
    assert device_report.detected_by_hash_chain


def test_deleted_middle_record_is_detected_by_chain_or_sequence():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(tamper_delete_record(secure_records), anchor)
    assert not report.ok
    assert report.detected_by_hash_chain or report.detected_by_sequence


def test_deleted_last_record_is_detected_by_trusted_anchor():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(tamper_delete_last_record(secure_records), anchor)
    assert not report.ok
    assert report.detected_by_hash_chain
    assert not report.anchor_ok


def test_inserted_duplicate_record_is_detected():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(tamper_insert_duplicate_record(secure_records), anchor)
    assert not report.ok
    assert report.detected_by_hash_chain or report.detected_by_sequence


def test_swapped_records_are_detected():
    records = generate_sensor_records(20)
    secure_records, anchor = secure_log_records(records)
    report = verify_full_log(tamper_swap_order(secure_records), anchor)
    assert not report.ok
    assert report.detected_by_hash_chain or report.detected_by_sequence

