# Package verification results

Date: 2026-10-17. Package contract: 1.0.0.

These tests exercise the handoff's reference contracts and SQLite persistence only.
Production GRE/NAT/QoS, VM reboot, watchdog recovery and uninstall integration are NOT RUN because the production application is the requested next implementation deliverable.

## Contract suite

Command: `python3 -m unittest discover -s tests -v`

Result: PASS

```text
test_frozen_resource_names (test_contract.IdentityContract.test_frozen_resource_names) ... ok
test_masks_isolate_tunnels_and_classes (test_contract.IdentityContract.test_masks_isolate_tunnels_and_classes) ... ok
test_no_id_wraparound (test_contract.IdentityContract.test_no_id_wraparound) ... ok
test_application_strings_are_ascii (test_contract.PackageContract.test_application_strings_are_ascii) ... ok
test_disabled_forward_still_reserves_tuple (test_contract.PackageContract.test_disabled_forward_still_reserves_tuple) ... ok
test_examples_validate_against_schemas (test_contract.PackageContract.test_examples_validate_against_schemas) ... ok
test_main_menu_has_exactly_four_actions (test_contract.PackageContract.test_main_menu_has_exactly_four_actions) ... ok
test_reference_is_network_read_only (test_contract.PackageContract.test_reference_is_network_read_only) ... ok
test_schema_rejects_bool_as_id (test_contract.PackageContract.test_schema_rejects_bool_as_id) ... ok
test_statistics_schema_allows_unknown_rate (test_contract.PackageContract.test_statistics_schema_allows_unknown_rate) ... ok
test_statistics_schema_and_windows (test_contract.PackageContract.test_statistics_schema_and_windows) ... ok
test_ui_golden_menus (test_contract.PackageContract.test_ui_golden_menus) ... ok
test_unknown_config_key_rejected (test_contract.PackageContract.test_unknown_config_key_rejected) ... ok
test_candidates_skip_collisions (test_contract.PeerContract.test_candidates_skip_collisions) ... ok
test_conflict_token (test_contract.PeerContract.test_conflict_token) ... ok
test_corrupt_or_oversized_token_rejected (test_contract.PeerContract.test_corrupt_or_oversized_token_rejected) ... ok
test_default_route_is_not_address_conflict (test_contract.PeerContract.test_default_route_is_not_address_conflict) ... ok
test_duplicate_json_keys_rejected (test_contract.PeerContract.test_duplicate_json_keys_rejected) ... ok
test_inside_assignment_is_reversed (test_contract.PeerContract.test_inside_assignment_is_reversed) ... ok
test_invalid_peer_addresses (test_contract.PeerContract.test_invalid_peer_addresses) ... ok
test_pair_is_symmetric (test_contract.PeerContract.test_pair_is_symmetric) ... ok
test_semantic_token_mismatch_rejected (test_contract.PeerContract.test_semantic_token_mismatch_rejected) ... ok
test_token_matches_frozen_example (test_contract.PeerContract.test_token_matches_frozen_example) ... ok
test_batch_limit (test_contract.PortContract.test_batch_limit) ... ok
test_invalid_golden_inputs (test_contract.PortContract.test_invalid_golden_inputs) ... ok
test_limits (test_contract.PortContract.test_limits) ... ok
test_valid_golden_inputs (test_contract.PortContract.test_valid_golden_inputs) ... ok
test_bad_interval_rejected (test_contract.StatisticsContract.test_bad_interval_rejected) ... ok
test_current_speed (test_contract.StatisticsContract.test_current_speed) ... ok
test_database_survives_reopen (test_contract.StatisticsContract.test_database_survives_reopen) ... ok
test_decimal_display (test_contract.StatisticsContract.test_decimal_display) ... ok
test_frozen_window_fixtures (test_contract.StatisticsContract.test_frozen_window_fixtures) ... ok
test_overlap_rejected (test_contract.StatisticsContract.test_overlap_rejected) ... ok
test_reset_and_epoch_change (test_contract.StatisticsContract.test_reset_and_epoch_change) ... ok

----------------------------------------------------------------------
Ran 34 tests in 0.035s

OK
```

## Consistency and packaging

The distribution is checked with `python3 tests/verify_package.py`, Bash syntax checks for the two supplied launcher/test templates, and archive CRC/path/inventory verification. SHA256SUMS lists the complete distributed file set except itself. These checks validate the package, not a live network implementation.
