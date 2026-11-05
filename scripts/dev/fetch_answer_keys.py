#!/usr/bin/env python3
"""Fetch the answer keys a test grades JMo against.

    python scripts/dev/fetch_answer_keys.py [key ...]      (default: every key)

An answer key is somebody else's file, pinned by commit and checked against a
sha256 each, kept in `$JMO_ANSWER_KEYS_DIR` or `~/.cache/jmo-answer-keys`, as
`<root>/<key>/<commit>/<path>`. Never inside the repository: sca-kitchen-sink's
lockfiles are vulnerable on purpose, so tracking them would raise Dependabot
alerts on JMo's own repository, vibeproof's fixtures hold three Postgres URIs
that trufflehog finds, and KICS's samples are misconfigured Dockerfiles that
JMo's own hadolint and trivy would report. A test whose key is absent skips and names the
command above.

A file is written only after its bytes match the pin: they go to a temporary
name beside it and are renamed once they verify, so a bad download never
replaces a good file and never leaves one behind. A file already there with the
right hash is left alone.

To add a key: a pinned table, one function that takes an optional cache root and
returns the problems it met, and a line in `KEYS`.

Exit status: 0 when every key is in place; 2 when a file could not be fetched,
did not match its pin or could not be written, or a key is unknown (each is
named on stderr, with the expected and actual sha256 for a mismatch).
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path, PureWindowsPath

ROOT = Path(__file__).resolve().parents[2]

# Run directly (`python scripts/dev/fetch_answer_keys.py`) and sys.path[0] is
# scripts/dev, not the repo root - so scripts.dev is not importable without
# this. Same bootstrap as scripts/dev/generate_baseline.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(ROOT))

from scripts.dev.fetch_rule_fixture import fetch_bytes  # noqa: E402

ENV_VAR = "JMO_ANSWER_KEYS_DIR"

SCA_KITCHEN_SINK = "sca-kitchen-sink"
SCA_KITCHEN_SINK_COMMIT = "eeddfe4d92fddb749915a98a7b02956eae33af22"
SCA_KITCHEN_SINK_URL = (
    "https://raw.githubusercontent.com/QuackatronHQ/sca-kitchen-sink/{commit}/{path}"
)
# Every lockfile JMo reads that the repository holds, plus `API.deps.json`. The
# hashes were measured on the blobs at the commit above.
SCA_KITCHEN_SINK_FILES: dict[str, str] = {
    "javascript/bun/bun.lock": "f60e983fdbc743305f69481098d1126e5c8bfddf4ba1fc6bd13102039301e6b2",
    "javascript/npm/package-lock.json": "d902e7fe5d92a8d8c4d55aa46ca09bf9990cc6e70a5fedee240f6ca50afdc186",
    "javascript/pnpm/pnpm-lock.yaml": "9d0d14d563bcd233ffeddf3d5a894e6a545aafff99235bcde339304f8f07fbb5",
    "javascript/yarn/yarn.lock": "0f7c81d49b057808f9df6c688d09bd61b0279a6d582045d1e9b097768d6d6cad",
    "python/poetry/poetry.lock": "f8fcabd308d502096bd65822974adb24ac1d1be6abf7f393ae4d15fcda4e605b",
    "python/requirements/requirements.txt": "d338c871ed94be536d5cd7b901a345e67e9812762a6ba11dbad9a153f577ed6a",
    "python/uv/uv.lock": "1e00596a0c12e5a8b3d93274cf227e39aed36d881782e0c1733b34e73b868763",
    "golang/gomod/go.mod": "cb84d8f779bbac9664bbdadd5cc7a6591fc338339d2f08d7a0e784b19b36028b",
    "rust/cargo/Cargo.lock": "4ff080a86fc7b1113cfb41d8454497515d3767327fc0a0b09f7d4b3095f78f83",
    "php/composer/composer.lock": "cf772f5844d21f6dd771e40c5e2e515fcca943fe7721ab9cff9a00e7d5163622",
    "ruby/rubygems/Gemfile.lock": "6bd0ea1183d4d1b99d4591e6acd566f436bfe0c015996263c3298458b0ca16d7",
    "java/maven/pom.xml": "edaea3447b03a1e0c3edde7f01979ebca8267d577e22831a76900c26e5d285e7",
    "java/gradle/gradle.lockfile": "987bfcd33f406eb9301694de063dc4ba72b90ddd5f4c6d88a754f2409141ad21",
    "csharp/nuget/packages.lock.json": "01ab79293636104a01dd680fc0cda9f06ee489598bea0df5646fabee5b2c4f0d",
    "csharp/nuget/packages.config": "57be95d533bdb4ffe39c7957f6098a490d29ede41fca9106deb273e7603e9303",
    "csharp/API.deps.json": "400975c04be8a4e64d25f0403712417465071eb20726054d9e9f8ed091f35954",
}

VIBEPROOF = "vibeproof"
VIBEPROOF_COMMIT = "2c57bfae70ab9bb1e059f8522fe1603b613ac42a"
VIBEPROOF_URL = "https://raw.githubusercontent.com/humora2504/vibeproof/{commit}/{path}"
# humora2504/vibeproof (MIT): the fixtures its own test suite scans, a vulnerable
# project and a clean one. The hashes were measured on the blobs at the commit
# above. `vulnerable/env.fixture` and `clean/env.example.fixture` carry tokens in
# place of credentials; the test that reads them builds the real files.
VIBEPROOF_FILES: dict[str, str] = {
    "test/fixtures/.gitignore": "3ee3be110dc18537e0ce3a2f027c8235143e348b162d4825a8e0af42973cf757",
    "test/fixtures/clean/.gitignore": "18d08748340596f6fc068ee2304c4a3e34e58c207df214f491587ece87ab47b1",
    "test/fixtures/clean/env.example.fixture": "68022d12b3f58bffcf1c935a84ddd90adf64af14fb5a8753fbb1e85ffa30c8dd",
    "test/fixtures/clean/package.json": "f500958b6425dcaa338f4fdee28ee4d482b6e61c7a828dd24cff2f28cb20a3c4",
    "test/fixtures/clean/src/app/api/items/route.ts": "7651d37a392613ba5e0952ba8d628c97cbcf1d4076cdfe3101db825ad19b6525",
    "test/fixtures/clean/src/lib/server.ts": "e587c5d734c8a1cca41b69196032fe4c07dd20f559012a7e2511d907b5b67efa",
    "test/fixtures/clean/supabase/migrations/001_init.sql": "4fa94c8224fca29fc786516eb86c585dd3a9f6ad6057fc01f7af2bf2295a5c8c",
    "test/fixtures/vulnerable/.gitignore": "16d30e4462189fb14dd611bdb708c510630c576a1f35b9383e89a4352da36c97",
    "test/fixtures/vulnerable/env.fixture": "aea8e768ca79e30342d0636bc9cf2e42e7bdffe7a4838005e0bfd53b80faa880",
    "test/fixtures/vulnerable/firestore.rules": "cc6e6efc37538d8041a014b7b30ae5ee746490d84f6e8c0643de0e5068440a5d",
    "test/fixtures/vulnerable/package.json": "2e6fcb50347744a4a9c8bb0a69a3a28ac0f22a3397aa5c95f88ea9fdf73ab6c3",
    "test/fixtures/vulnerable/src/app/api/delete/route.ts": "13752f3f1ffff75a8c803064210ed5d27a1319fe782642b4b809dca35550cee8",
    "test/fixtures/vulnerable/src/lib/admin.ts": "359dd0fa7a39f99198960b0530d77e75aa469904532b025db903bd58035fbf10",
    "test/fixtures/vulnerable/supabase/migrations/001_init.sql": "365428d836db5f6dd43c0fb9360b80d8ef9135fb3fc1dcc18e0f150ba7e6bda9",
}

KICS = "kics"
KICS_COMMIT = "453066aa9c66014ad7aee7dd0149ba1944c78050"  # v2.2.0
KICS_URL = "https://raw.githubusercontent.com/Checkmarx/kics/{commit}/{path}"
# Checkmarx/kics (Apache-2.0): for each of its 48 Dockerfile queries, the
# positive samples and the lines a scanner should flag in them
# (`positive_expected_result.json`), graded by
# tests/integration/test_kics_line_floor.py (Phase 6, E6). The hashes were
# measured on the blobs at the commit above.
KICS_FILES: dict[str, str] = {
    "assets/queries/dockerfile/add_instead_of_copy/test/positive1.dockerfile": "8a34bc7644cde34f4baf231fea1d0cb51d6fb7c33e02ace10f54c16f5078aa42",
    "assets/queries/dockerfile/add_instead_of_copy/test/positive2.dockerfile": "2a7230451ad8b6726386f2bcb5850132a359bbf596dd58174d7a631f635abf1d",
    "assets/queries/dockerfile/add_instead_of_copy/test/positive_expected_result.json": "01377c729b966a1f2888b724116d440b067df104b96fd80f3bbc8402935e2445",
    "assets/queries/dockerfile/apk_add_using_local_cache_path/test/positive1.dockerfile": "789c7f7508e48185e8b33be0010de98a82e7532c49d5782fa9a97a55bf2ff4b4",
    "assets/queries/dockerfile/apk_add_using_local_cache_path/test/positive2.dockerfile": "09c784ec417488cea99173f13f57759d0062d806dd19283fe2bfc204ed6eedfc",
    "assets/queries/dockerfile/apk_add_using_local_cache_path/test/positive3.dockerfile": "82034087f0d4aa6a046828fe9f6daf1e30d088e5f9f81459074547efaee2871f",
    "assets/queries/dockerfile/apk_add_using_local_cache_path/test/positive_expected_result.json": "8ce92027afef49d418c144f34fe42f3ba9f43ca45ecdde856c3b5679878cd7c5",
    "assets/queries/dockerfile/apt_get_install_lists_were_not_deleted/test/positive1.dockerfile": "be502039fecb4aea7dd5454f2608b13212740f9bbc0b5e69bc0e65b2679d8875",
    "assets/queries/dockerfile/apt_get_install_lists_were_not_deleted/test/positive2.dockerfile": "90543a2579243c76485aa3f6271c7bfff2f6fe16ed584e7176d528da16bf8f9a",
    "assets/queries/dockerfile/apt_get_install_lists_were_not_deleted/test/positive3.dockerfile": "35342bc4978936c1acb4d795e4342dff62bfe89d785910667ca9fd3f8d5b6258",
    "assets/queries/dockerfile/apt_get_install_lists_were_not_deleted/test/positive_expected_result.json": "014ba790813a80a72bfcf63e65ad1a5a32344bbe05c811d7ea18bbe1092e8e70",
    "assets/queries/dockerfile/apt_get_install_pin_version_not_defined/test/positive1.dockerfile": "3bf5a77d6236319c367e85c7fa9d87d69feee074ce9b66c11a0bd49c15307526",
    "assets/queries/dockerfile/apt_get_install_pin_version_not_defined/test/positive2.dockerfile": "2ec4ebec1bde0df621f753a78214437f5fa5ef1268d5c5e0a9d9451a130a77a7",
    "assets/queries/dockerfile/apt_get_install_pin_version_not_defined/test/positive3.dockerfile": "cd2a342b6186e0c4361b4da2506643e79e995d507621b5c2572fec68c41fface",
    "assets/queries/dockerfile/apt_get_install_pin_version_not_defined/test/positive_expected_result.json": "c60128ea066fefa8753b24fc4aa8762b616484a717514a4b1211c5a629f0e232",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive1.dockerfile": "458c18b105983e6b31abead7cca033b53eb23a22032e44dd84eb16e94986b3a6",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive2.dockerfile": "bafc4dcebd4eec8943456a17841a38c585d529f9dfc952cce29b481fe13d856f",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive3.dockerfile": "f05a55a5e90d7d23e117722c9697bbda780cad817b8628be2acd394b7cbb3b3f",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive4.dockerfile": "90367557805c5a2ef4036bef64d55b686b70fc39a5723e65f3f0684b4ab1344c",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive5.dockerfile": "5104d205c324f97484f6da865fe9723c4889fa1a6b5cb6d02f0549695ebda9f1",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive6.dockerfile": "f485ce1946678e1b02ed6f2ea250aafd15dff4fa6248000af37d4e1776262adc",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive7.dockerfile": "707eb6172250baecfbb83c110949293e8f30309e50f2245bbb5d9e645c209849",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive8.dockerfile": "e552cc95979ae298d6350cafee23d91594ba951725a26d689053744a1be95a3a",
    "assets/queries/dockerfile/apt_get_missing_flags_to_avoid_manual_input/test/positive_expected_result.json": "f0332043e1b098cfb9393c2f31b1f10e8c4bcac9c8e116694f2077aeb89c5331",
    "assets/queries/dockerfile/apt_get_not_avoiding_additional_packages/test/positive1.dockerfile": "bef03e5364d5c2df98d74907e40d1287608b2d4e6c5d7d333a9bf0d7da85fc09",
    "assets/queries/dockerfile/apt_get_not_avoiding_additional_packages/test/positive2.dockerfile": "5fa91244a0e05c51132edd4b297bebfe5da54b1124637a3b8cbf49e9ee907d2a",
    "assets/queries/dockerfile/apt_get_not_avoiding_additional_packages/test/positive_expected_result.json": "80acefa6c6c39ca67c1dafe6a47063912d61598a84db85cc2d441203551e2032",
    "assets/queries/dockerfile/changing_default_shell_using_run_command/test/positive1.dockerfile": "35198fdde184c080efd9a92c5a6585aa9c9812a6987aa5b772d56c64ca149429",
    "assets/queries/dockerfile/changing_default_shell_using_run_command/test/positive2.dockerfile": "84433a5e79b7baf8a9fdf84123dbd7b12f55d405f150d2f82218670c43685c44",
    "assets/queries/dockerfile/changing_default_shell_using_run_command/test/positive3.dockerfile": "222ecb64a93f5201250dda20b7a78b3e705517382d478c1c238118ca98c7e9a8",
    "assets/queries/dockerfile/changing_default_shell_using_run_command/test/positive_expected_result.json": "4cc0dbebf6822c8f08f062cf22811aaf99a91066823731d3457c0222754945e2",
    "assets/queries/dockerfile/chown_flag_exists/test/positive1.dockerfile": "72eb9179c66bfbfbb5c7d61ba3e3164eb59f1486df953bd5c37f73106d739581",
    "assets/queries/dockerfile/chown_flag_exists/test/positive2.dockerfile": "f3423ddeb942c66a4336bfdb439bae76749aec206a1490338237b81166af4ce4",
    "assets/queries/dockerfile/chown_flag_exists/test/positive_expected_result.json": "266a3f02dfbd278525b1726d3fb3b5193d543dfc9a048d48aef5f63b7194354e",
    "assets/queries/dockerfile/copy_from_references_current_from_alias/test/positive1.dockerfile": "9e41943944747712e07b9b008fefb9c23795a8809feec0742818a819433e2d95",
    "assets/queries/dockerfile/copy_from_references_current_from_alias/test/positive2.dockerfile": "0525cc77702c80869c013619b86c689212bfe3026565d014feaad6660705967d",
    "assets/queries/dockerfile/copy_from_references_current_from_alias/test/positive_expected_result.json": "bf1036431f9438b32e9fdd0eeee3a7684c1edef518dc918a7e96c003e5dad37e",
    "assets/queries/dockerfile/copy_with_more_than_two_arguments_not_ending_with_slash/test/positive1.dockerfile": "d34ee26cfc677b441bb235df570b5d1eb22b6d359097c441dc5e54c4a329a5b5",
    "assets/queries/dockerfile/copy_with_more_than_two_arguments_not_ending_with_slash/test/positive2.dockerfile": "f8dbbb2b6b8358e34c03c44cb15f4b3795dd2f4a4af5833bfc0147880945d926",
    "assets/queries/dockerfile/copy_with_more_than_two_arguments_not_ending_with_slash/test/positive3.dockerfile": "21e515da93c9f318337b2bd65e33c69bda944a1c23e990b0e75d9dd9a06a4498",
    "assets/queries/dockerfile/copy_with_more_than_two_arguments_not_ending_with_slash/test/positive4.dockerfile": "25a84c7461b4736e52328f053de3ec282b4ddab616e29ac29dd87138f71762a7",
    "assets/queries/dockerfile/copy_with_more_than_two_arguments_not_ending_with_slash/test/positive_expected_result.json": "278bb06c2f0bbc92630077530bb9b427a3e8771567e3c1d33133e2cad3532425",
    "assets/queries/dockerfile/curl_or_wget_instead_of_add/test/positive1.dockerfile": "bcb028eaf8cd48478b42cc238dac4c99e5590d0d082c03461389ad7e5eadcc1e",
    "assets/queries/dockerfile/curl_or_wget_instead_of_add/test/positive2.dockerfile": "3219491ac7953e358fd3a45a6f29d4d2114620eace0ce517adcef187c1c01242",
    "assets/queries/dockerfile/curl_or_wget_instead_of_add/test/positive_expected_result.json": "6b6a65b38253888b30c29a6cad1f7ed9a64347d4e9021c33d272af9bacac882e",
    "assets/queries/dockerfile/exposing_port_22/test/positive1.dockerfile": "9a0383c78c1e67f122fdbfa32e2d1344b2dbd9682b37b43e7ff3d9518b9eb2bd",
    "assets/queries/dockerfile/exposing_port_22/test/positive2.dockerfile": "1d7119c8440f5fe40bc163e39742717880ed730df1e1c3d92466079334dd75ce",
    "assets/queries/dockerfile/exposing_port_22/test/positive_expected_result.json": "159d55f024663d4c43dda09bb3b5b10a0867a47488b33313762981e3ce48d412",
    "assets/queries/dockerfile/gem_install_without_version/test/positive1.dockerfile": "f783e817a6d877390dfc7c1399d5a81d97608d19e8c335011e7d4b2f7b5ff7d0",
    "assets/queries/dockerfile/gem_install_without_version/test/positive2.dockerfile": "97de4ea818e071e7514624a30b64ca2a8035dfa3b67e4ea194e56ccf815f6f34",
    "assets/queries/dockerfile/gem_install_without_version/test/positive_expected_result.json": "a2fc642f4307ba53935a6f9606dde2126f53d69fea148a89af167cc4f6b838c6",
    "assets/queries/dockerfile/healthcheck_instruction_missing/test/positive1.dockerfile": "5b0b357b13fe398663e6b96ce19428cbc29018f754578c25fe6ade58ab5c2ba7",
    "assets/queries/dockerfile/healthcheck_instruction_missing/test/positive2.dockerfile": "62b1a14d2786c0aac26f4e8c725ea8cb62afe213133b602dc5a4c0581920c7e4",
    "assets/queries/dockerfile/healthcheck_instruction_missing/test/positive3.dockerfile": "764275a0f3799c94744ae9eaa30074442cc088a17ec23767926fcfe019f18ae0",
    "assets/queries/dockerfile/healthcheck_instruction_missing/test/positive_expected_result.json": "01fcd3238cf170045c4eb574ba91d8fa4dce9cff7c777b491d5ed938bdc14866",
    "assets/queries/dockerfile/image_version_not_explicit/test/positive1.dockerfile": "55f76ebfcd0abdf0f160ef14f00be528287ddba2f88a09309529dd216b01eef0",
    "assets/queries/dockerfile/image_version_not_explicit/test/positive2.dockerfile": "1beb06002cd4da424647dd5ff9b433e113c3c860cde5c258af1f54d80b56a789",
    "assets/queries/dockerfile/image_version_not_explicit/test/positive3.dockerfile": "77123b47d1c3f96a14379b58af102a1a07771c0cd7939ff1a2d76b446fb3ad25",
    "assets/queries/dockerfile/image_version_not_explicit/test/positive4.dockerfile": "8db7140951b2d3ec42cd4870a3e55dbcaf4ea419b0afba120a63491b6726499d",
    "assets/queries/dockerfile/image_version_not_explicit/test/positive5.dockerfile": "b5015fd339583b48e666c59d729563abd64ebc7ccf743e9781dd66134f42bf3d",
    "assets/queries/dockerfile/image_version_not_explicit/test/positive_expected_result.json": "75391e0dc91d93d06db7d4c4b6d43a1e08ebb89a548916eb50fb31ff440e6704",
    "assets/queries/dockerfile/image_version_using_latest/test/positive1.dockerfile": "8d9b66b41740f8fdad5b5eed0503fdbd54c9e5ed68df22d740e2f516e1c951da",
    "assets/queries/dockerfile/image_version_using_latest/test/positive2.dockerfile": "0dd1b4daf0d931df34174eb2d0676174aae7335c0870b9574d9b63b46fbe9650",
    "assets/queries/dockerfile/image_version_using_latest/test/positive_expected_result.json": "458640d6fa232f58a6dd80e9d1120dcbd3bca09ffbda04e10bc61114985b6358",
    "assets/queries/dockerfile/last_user_is_root/test/positive1.dockerfile": "e9d57878408df666d9b5eb5f2db35c1c1666920354829b1053456df5505b9467",
    "assets/queries/dockerfile/last_user_is_root/test/positive2.dockerfile": "26dceafe96440f8e5962277eeffe1589f1fdc4fecd9b5142de5d946028503770",
    "assets/queries/dockerfile/last_user_is_root/test/positive3.dockerfile": "2826736e67ed11ea8d0530a98bd64925651e147f2bdf0761fd752d38d056b4b5",
    "assets/queries/dockerfile/last_user_is_root/test/positive4.dockerfile": "6115134b3792569f94474910496a37c3e3b0a361487c6f1b6114a6d889aed221",
    "assets/queries/dockerfile/last_user_is_root/test/positive5.dockerfile": "42737d4e1701b938ffcddf9533a6df993a0f59b60ad0546b64e720900b92f34a",
    "assets/queries/dockerfile/last_user_is_root/test/positive_expected_result.json": "d3a548d1dc5a824f5dfae96c1442dea4c651201cafbe3f2653e1efb8752be93a",
    "assets/queries/dockerfile/maintainer_instruction_being_used/test/positive1.dockerfile": "98611edd0addc84611c510803a5677499c8af247b5352ed53daa840683797c00",
    "assets/queries/dockerfile/maintainer_instruction_being_used/test/positive2.dockerfile": "89d746af66ef94a7ce25ab9572b31d60c7ff1d1e89ab5e057297e08059581df5",
    "assets/queries/dockerfile/maintainer_instruction_being_used/test/positive_expected_result.json": "147f56c74013e4d8d0d9eb60dc1d896124db66c8601033eec2dea8a5be8e597f",
    "assets/queries/dockerfile/missing_dnf_clean_all/test/positive1.dockerfile": "f9f591f2770a5b1f40770dade77370aa8d058b4e247a8aed1585ea31d1428601",
    "assets/queries/dockerfile/missing_dnf_clean_all/test/positive2.dockerfile": "7a5b62b865afe0fda7d90362433277fa6e0c6db6a8ea272140844e25dcfea8e3",
    "assets/queries/dockerfile/missing_dnf_clean_all/test/positive_expected_result.json": "989d177ba0c3ab808790aec2a71728c5fe1820411b325fb603370759e67b3362",
    "assets/queries/dockerfile/missing_flag_from_dnf_install/test/positive1.dockerfile": "366a14323bb9345fbe1df90dbf0fd8a40484b1487836502227b79e15839703ea",
    "assets/queries/dockerfile/missing_flag_from_dnf_install/test/positive2.dockerfile": "9c7ea5ad2469a49e382a6a75e156f70649a0c7d8271b087cc7ee2b0b769252f1",
    "assets/queries/dockerfile/missing_flag_from_dnf_install/test/positive3.dockerfile": "bae9902051de0c56a0f33f05dee0f0bfc86bf2757edd80090bcceb3736a64732",
    "assets/queries/dockerfile/missing_flag_from_dnf_install/test/positive4.dockerfile": "f2d85b422da470f24272550e339e59da8e42eb851da7567bf2297111f5357870",
    "assets/queries/dockerfile/missing_flag_from_dnf_install/test/positive5.dockerfile": "47dc449274b439b40cdf1173f29f5e69664ba960d69e1c13deb804efcddfa55e",
    "assets/queries/dockerfile/missing_flag_from_dnf_install/test/positive_expected_result.json": "2f84e1cf9697d82745ae6ec9b82002d50542a5e07e2a6cd7329b72ab6356c1b0",
    "assets/queries/dockerfile/missing_user_instruction/test/positive1.dockerfile": "d0d4d475f8cf49b14a57dcd92860175736b6f4f58408923a8f5428f679d70cfd",
    "assets/queries/dockerfile/missing_user_instruction/test/positive2.dockerfile": "264b9d0b420e47c1b8149ddf9e98346db6851dbf4b105e1bdc5740188f187adf",
    "assets/queries/dockerfile/missing_user_instruction/test/positive3.dockerfile": "0d6977d4b0e136491c0491353530d021a12e65a6172d9c91ac4a812529e54fba",
    "assets/queries/dockerfile/missing_user_instruction/test/positive_expected_result.json": "4b62c12cf87d936bd39beb6643ab06c78f8fa9db6dc3a33934c24f85ca413713",
    "assets/queries/dockerfile/missing_version_specification_in_dnf_install/test/positive1.dockerfile": "0879ceb6b6a9acb40baec84908c9efdeab3d90b1efaf555a8888e47d5fa905ff",
    "assets/queries/dockerfile/missing_version_specification_in_dnf_install/test/positive2.dockerfile": "97495746043176261dbce2e3a67e0563e77cb09d6162186862e1441380c1851d",
    "assets/queries/dockerfile/missing_version_specification_in_dnf_install/test/positive_expected_result.json": "009089cf686134296bbe6a9a9848be51a2f7f305bc583ad2a26a90c0481abc79",
    "assets/queries/dockerfile/missing_zypper_clean/test/positive1.dockerfile": "1c47da37ae28c40f1becaa8093a1c448af1d96bb28e2ea02c7745229cd154ef4",
    "assets/queries/dockerfile/missing_zypper_clean/test/positive2.dockerfile": "c7160d4d512cc20fd5db00e54e06b3a57c98f67c11cdd5f847ec483b9ddb9d81",
    "assets/queries/dockerfile/missing_zypper_clean/test/positive_expected_result.json": "a16a0ea880644ecca0dfa34121a2220baa2518f71075b1b1cea57ffaae79072f",
    "assets/queries/dockerfile/missing_zypper_non_interactive_switch/test/positive1.dockerfile": "393000003da92f008c49918932936bf1e655a777f472e5cdee417fd18fc683bd",
    "assets/queries/dockerfile/missing_zypper_non_interactive_switch/test/positive2.dockerfile": "ebea02360477d32ed6b6a1b01eef68fb6053482d7fc612b1dacdde5de9aff65e",
    "assets/queries/dockerfile/missing_zypper_non_interactive_switch/test/positive_expected_result.json": "cdb3299fa535e1b7663d87fd893fa0b51272741fa60a7c0ff65afc8b56c805b2",
    "assets/queries/dockerfile/multiple_cmd_instructions_listed/test/positive1.dockerfile": "3612696b7e99a5eafe14c40e017a765cffce7dc57775950e4260c6cd03f88cfa",
    "assets/queries/dockerfile/multiple_cmd_instructions_listed/test/positive2.dockerfile": "1698abb7d5325d9d81c86bc4bee8fd0ee48eec79a2d34a49ebf5e7a64fc4edc1",
    "assets/queries/dockerfile/multiple_cmd_instructions_listed/test/positive_expected_result.json": "bd9073467d8d40dc4f2337ddd6f5ad94941405cfa1a7651c0e1daf544f36365c",
    "assets/queries/dockerfile/multiple_entrypoint_instructions_listed/test/positive1.dockerfile": "296f816fa9f90287ed129fcc934e9d58b9516ca81bc46e48c8d0c2111ee10e89",
    "assets/queries/dockerfile/multiple_entrypoint_instructions_listed/test/positive2.dockerfile": "66749fa34d7d21367d3070360d00aebc37bc6b79fc06ad9ebb20ba70a7ed4443",
    "assets/queries/dockerfile/multiple_entrypoint_instructions_listed/test/positive_expected_result.json": "920ee613034ab3a554388c6966ac3804b7bc7ae03be8d75b321cb2c0c60cd419",
    "assets/queries/dockerfile/multiple_run_add_copy_instructions_listed/test/positive1.dockerfile": "728c3031e5070e86b94d545b6d56172b798991b5b4f85f2c7461ccc9bb60e121",
    "assets/queries/dockerfile/multiple_run_add_copy_instructions_listed/test/positive2.dockerfile": "fe15bbd004aa735f937a6fd5f33d5897fb28191e782393bff98d4c8cbe5a962d",
    "assets/queries/dockerfile/multiple_run_add_copy_instructions_listed/test/positive3.dockerfile": "7592a240588cb84fbe7356ca03051c6de3469d22e51c90661e9df01a81405bec",
    "assets/queries/dockerfile/multiple_run_add_copy_instructions_listed/test/positive4.dockerfile": "b4b11c5cc5127600ccc8b7338e158261bce4eaee716f97169838e0adeec4e79a",
    "assets/queries/dockerfile/multiple_run_add_copy_instructions_listed/test/positive_expected_result.json": "d6e9a98036c9e58d2f0254eed0ec7f128f054ccbd6fd6b002df3cfbb48acd7cf",
    "assets/queries/dockerfile/not_using_json_in_cmd_and_entrypoint_arguments/test/positive1.dockerfile": "cc1afe65ce02a0495772eeb59e4f724c6a85fc50b59d740f819d9944cd5f837f",
    "assets/queries/dockerfile/not_using_json_in_cmd_and_entrypoint_arguments/test/positive2.dockerfile": "f89a370fb0c393cd65d83a4d2707c234fcd2b77b6f6318d8a667f2458ffdafee",
    "assets/queries/dockerfile/not_using_json_in_cmd_and_entrypoint_arguments/test/positive_expected_result.json": "ea61fd84bf9217d35fda3cdc1eaabd2d03df0581e7d3d2b4fd37db552bdeb263",
    "assets/queries/dockerfile/npm_install_without_pinned_version/test/positive1.dockerfile": "9ba42bca392eaa9013f3b51d737604bbcf6739815eb8a8422dc0abca5e4bc732",
    "assets/queries/dockerfile/npm_install_without_pinned_version/test/positive2.dockerfile": "598bacaedd3e40ee4b2344469443cc6a4fb4504419e05aa903fef3aa29d0902d",
    "assets/queries/dockerfile/npm_install_without_pinned_version/test/positive_expected_result.json": "67c107492ea8b3d4169ceb4058d3ee600a82a689172c32c1fecd76b7427034af",
    "assets/queries/dockerfile/pip_install_keeping_cached_packages/test/positive1.dockerfile": "68223a817c89b0a270791d1c4b16b75ff94956c75e3fae0078edc0602b4fa186",
    "assets/queries/dockerfile/pip_install_keeping_cached_packages/test/positive2.dockerfile": "ed20078482f5833405c82910f02287d04425ed3b125a9d030d3e877ae2fa503d",
    "assets/queries/dockerfile/pip_install_keeping_cached_packages/test/positive_expected_result.json": "69b1ad615f3b3b4953360408d8de8e25d5906bfeed82b3b5073747368d50a3b5",
    "assets/queries/dockerfile/run_command_cd_instead_of_workdir/test/positive1.dockerfile": "3b022a19eecf37ee80a30978f4deefe28416d48f1ba8befdfb26a51f92dd1124",
    "assets/queries/dockerfile/run_command_cd_instead_of_workdir/test/positive2.dockerfile": "eb2aff53ecf9cbb272b4914edd35c443e0aaa10f4727e542d879df1f0a9e906f",
    "assets/queries/dockerfile/run_command_cd_instead_of_workdir/test/positive_expected_result.json": "29a3861ef206329110f533e06fca8a1f7db6f311829c803778229e52b7e1ae94",
    "assets/queries/dockerfile/run_using_apt/test/positive1.dockerfile": "8292720c43ec3d8109f7f45c24b0fd19c7d24ab438013271fb1ca42f7ba0f2a8",
    "assets/queries/dockerfile/run_using_apt/test/positive2.dockerfile": "c6d7d4037a853386cf139a5f2c60e92d383c6dc24283c996a7ceca299203ac7e",
    "assets/queries/dockerfile/run_using_apt/test/positive_expected_result.json": "b8c53a801e0bb78d805b11c7f34f5691596a24cf00c2dd276ad3224531f0f434",
    "assets/queries/dockerfile/run_using_sudo/test/positive1.dockerfile": "47996354f8caddf7968d8939872b8701da2077e6dbb0452ace08c06ce14a29a4",
    "assets/queries/dockerfile/run_using_sudo/test/positive2.dockerfile": "941b90d55c092d45487f3deb5556bf55eeb3485b732a57bc05bff58837a5c2f5",
    "assets/queries/dockerfile/run_using_sudo/test/positive3.dockerfile": "09938cb6db249f6bec549199f63a82c1f00d1fa4712d2965e3c614ce9e6d0179",
    "assets/queries/dockerfile/run_using_sudo/test/positive4.dockerfile": "a0aade684df08ff726e8cf434be3ac220961e0ce635af4def2a42e05d31d1fb4",
    "assets/queries/dockerfile/run_using_sudo/test/positive5.dockerfile": "8516a70941ae97f747bad3033a7b8b26d73d2bbe474e23b691d20c0e65d65778",
    "assets/queries/dockerfile/run_using_sudo/test/positive_expected_result.json": "37b601b6256c1a36c0bafbfeff7305d8c24c43069e671ac385c103b4623791f0",
    "assets/queries/dockerfile/run_using_wget_and_curl/test/positive1.dockerfile": "56fc71f8be80cd900cf69df0a91be9832f16135d6a52cfbf5ddb0f748caad384",
    "assets/queries/dockerfile/run_using_wget_and_curl/test/positive2.dockerfile": "774690b382281d21b2cb80721899ba5070370c12fb28cf9115175e922491ea39",
    "assets/queries/dockerfile/run_using_wget_and_curl/test/positive_expected_result.json": "319b90f3c9216c11d21661afc48233c5bac9325ba9b97522eb36df1cee35147a",
    "assets/queries/dockerfile/run_utilities_and_posix_commands/test/positive1.dockerfile": "735d4a2497174d3b4110ca16556b57898270a866e37c8f2f8a6185d08051b449",
    "assets/queries/dockerfile/run_utilities_and_posix_commands/test/positive2.dockerfile": "009abab2fa699f7cae74a8774e25b652984e5ce6a0870e86dd5cf68dc267498b",
    "assets/queries/dockerfile/run_utilities_and_posix_commands/test/positive_expected_result.json": "16c90548c2de792131b946decd2326e8b7454a47389b8fa314a643cd42f34462",
    "assets/queries/dockerfile/same_alias_in_different_froms/test/positive1.dockerfile": "80ddddb54ad71d78df3809b5c89749dbcf8300092f59729d48fb57e73a67d51d",
    "assets/queries/dockerfile/same_alias_in_different_froms/test/positive2.dockerfile": "fdad797ef550648e6ab4d964e93414bd98c53d30e0d11004c02f67baaf5765ec",
    "assets/queries/dockerfile/same_alias_in_different_froms/test/positive_expected_result.json": "bb960ca28a763d0873e3a320a1f7e71af04a03de11b8a5cf0e15cd35a2c25b14",
    "assets/queries/dockerfile/shell_running_a_pipe_without_pipefail_flag/test/positive1.dockerfile": "9706187e770056e9507d8b0f4d018ac8a9b0b891e7b3c6ba1567f0f5f9ccb01a",
    "assets/queries/dockerfile/shell_running_a_pipe_without_pipefail_flag/test/positive2.dockerfile": "fe4dab0da0317bd8771fe8f4e878c6aeec797eb5264336a748f7a91b1fb15528",
    "assets/queries/dockerfile/shell_running_a_pipe_without_pipefail_flag/test/positive_expected_result.json": "44bf2467ad63833c522d5e42e6c9c355b33df8bdb8cd176b826cda4ada65a1ea",
    "assets/queries/dockerfile/unix_ports_out_of_range/test/positive1.dockerfile": "59d4c2a835a98f1b12e451a6cfb0adb2dc8c8584e0944547ce003c9adb974faa",
    "assets/queries/dockerfile/unix_ports_out_of_range/test/positive2.dockerfile": "30d29a756a8d9f453160dccd9e6e157e21d77d59ec76d67de580535b569b370e",
    "assets/queries/dockerfile/unix_ports_out_of_range/test/positive_expected_result.json": "cc251f9e73c819e569408c94e84283f6df5773321fc5361f846a0ce0240860d3",
    "assets/queries/dockerfile/unpinned_package_version_in_apk_add/test/positive1.dockerfile": "282d56ccd8cce8d36b23e4e5be83fe0bcf0d6418a696c23dc46669488da3b26c",
    "assets/queries/dockerfile/unpinned_package_version_in_apk_add/test/positive2.dockerfile": "222b071b95868507df0c28942379f8bd86145477948ff5f9b71f79423ce4f54a",
    "assets/queries/dockerfile/unpinned_package_version_in_apk_add/test/positive_expected_result.json": "cca2bfb336e62e09aefdb1f04b058243efc1a0b2dd4e2acd8f849801335c6dc2",
    "assets/queries/dockerfile/unpinned_package_version_in_pip_install/test/positive1.dockerfile": "5c0b37f2aa5e66512dd3585105f31960eafb467e0e659257c04213fc9c4719a7",
    "assets/queries/dockerfile/unpinned_package_version_in_pip_install/test/positive2.dockerfile": "8ea1c8ffadd3c9cb6cd3859e24bd45324ebffba9b297c961983ed02bbb3517ad",
    "assets/queries/dockerfile/unpinned_package_version_in_pip_install/test/positive3.dockerfile": "9d39e578e99e92c5778a538330d1b514a67ab5dd7bc809d97c3ce2937b9cf438",
    "assets/queries/dockerfile/unpinned_package_version_in_pip_install/test/positive4.dockerfile": "83fe2d7767459c0b61761f5e5304635c85e265fea4946ec5e319f889c23b2892",
    "assets/queries/dockerfile/unpinned_package_version_in_pip_install/test/positive5.dockerfile": "025a634a772ecf12f0d19d7174b0bc30cfd219942a6c57cd74c3cab32c6b8198",
    "assets/queries/dockerfile/unpinned_package_version_in_pip_install/test/positive_expected_result.json": "1a5f8b786166e63079c23b8d90c47ad4103ece7f30fff0502d9009564570abdf",
    "assets/queries/dockerfile/update_instruction_alone/test/positive1.dockerfile": "f585962edb1a53e42d75b425287b565d2a13e90fd8629a111f0357a580b3755b",
    "assets/queries/dockerfile/update_instruction_alone/test/positive2.dockerfile": "ccc71878ede5a9ff2b4b4fe47fcf7a39cf0d5b56480aa0ec640f059ea5268e98",
    "assets/queries/dockerfile/update_instruction_alone/test/positive3.dockerfile": "d50a10803abd5714ef3f1046bea25dbfc1ce13381b090b28acb6e4e6e9ba1343",
    "assets/queries/dockerfile/update_instruction_alone/test/positive4.dockerfile": "dff343278fdc6e6125c8054b2c66fcf5251a1fb2931a81a780a82226551c7d9f",
    "assets/queries/dockerfile/update_instruction_alone/test/positive5.dockerfile": "2a4d7814b540e59128e2547dcfdf24836764d43c35433311897ed40cf4221cd9",
    "assets/queries/dockerfile/update_instruction_alone/test/positive6.dockerfile": "3d5fb7d5ccabf96b009fb60dbb2541b621a0d2b72887a0f68bddeddc543d8bea",
    "assets/queries/dockerfile/update_instruction_alone/test/positive7.dockerfile": "55783afa8f6422d5979b72236069494a6989ee147b01f65f6c042f18ee432891",
    "assets/queries/dockerfile/update_instruction_alone/test/positive8.dockerfile": "1bfca5de800937b934c68121811c1c8b18cbc8cae0cccc5cccc9be021c19d6a1",
    "assets/queries/dockerfile/update_instruction_alone/test/positive_expected_result.json": "6fb73435b66dfe5601030a859542a390f97aef6ec0df96e5ec77d9fb2a21a47b",
    "assets/queries/dockerfile/using_platform_with_from/test/positive1.dockerfile": "e682e3afc22cf48eb0e4232ccc8babcb2305da7fba6d3231fab58a07d47c3a14",
    "assets/queries/dockerfile/using_platform_with_from/test/positive2.dockerfile": "8b65c301c780c23cddb476d9e34d06868af8af77d4b8e309fbf51d20dd763388",
    "assets/queries/dockerfile/using_platform_with_from/test/positive_expected_result.json": "bafbd1d04ecaf8a02811ed7ced376132a035b66e3a35f818ab2cc31987fa3d89",
    "assets/queries/dockerfile/using_unnamed_build_stages/test/positive1.dockerfile": "42581a5cd4bbd432e296c499edd21b58e3669e0cbc71feb15279d606df37910a",
    "assets/queries/dockerfile/using_unnamed_build_stages/test/positive2.dockerfile": "f2a1fe71b4404577831a076f74f21f7b2c77d983ad094548670cf0f026b04fa6",
    "assets/queries/dockerfile/using_unnamed_build_stages/test/positive_expected_result.json": "01cb58377963ea08347e8f87c95f1a3f6e1f26f88ef50989120ca386cb8c5b3f",
    "assets/queries/dockerfile/workdir_path_not_absolute/test/positive1.dockerfile": "d2254e22cd39e2c2c9ce165602f2a736e7c4b6103e1088d79c45f8e301d2a8ae",
    "assets/queries/dockerfile/workdir_path_not_absolute/test/positive2.dockerfile": "425a917afbd6e9dc62516e41fabb547ec931b9726e9e9024e8ca671e0656b564",
    "assets/queries/dockerfile/workdir_path_not_absolute/test/positive_expected_result.json": "0f3e364c712b0df7e0b19b7ab64bc2e40844b3c51ee881de0ca00f6c6df4273a",
    "assets/queries/dockerfile/yum_clean_all_missing/test/positive1.dockerfile": "43b882dddf507f9e26ab94c700db3760b37918e008e412f8a03bcd050e5d709c",
    "assets/queries/dockerfile/yum_clean_all_missing/test/positive2.dockerfile": "e3a4b2914d273da38ab7b40622ad12adb4c43c690cd3e20251445619ef17e026",
    "assets/queries/dockerfile/yum_clean_all_missing/test/positive_expected_result.json": "c3177dcafb4aee4bf01f466a0591659658328f78b7704345ad4fa084b41523ef",
    "assets/queries/dockerfile/yum_install_allows_manual_input/test/positive1.dockerfile": "7e76f691bd6c41f337145823aadfd3a310f747d8200aa0589315942e0663b1b5",
    "assets/queries/dockerfile/yum_install_allows_manual_input/test/positive2.dockerfile": "4ef747bcbee79ac61171710ff24ea84e16ccc76ff8db3b47a3b32581f3750e3c",
    "assets/queries/dockerfile/yum_install_allows_manual_input/test/positive_expected_result.json": "b645398beaf509c74118944c8742c5a6a0c1efabcdef136e65dc0b1e3691b6e7",
    "assets/queries/dockerfile/yum_install_without_version/test/positive1.dockerfile": "f6ba37e2deb5af8b4c842a2eb9af50bee5bb35e77af79442060ddda124f63b21",
    "assets/queries/dockerfile/yum_install_without_version/test/positive2.dockerfile": "db4c7161fd0dfab8192b98dfe552db1d57a004b00b5382807152a7873e81bf94",
    "assets/queries/dockerfile/yum_install_without_version/test/positive_expected_result.json": "c548829923aa8258b6874cab32f99cecf964827c001b8611eb6ed8ddbacd30b8",
    "assets/queries/dockerfile/zypper_install_without_version/test/positive1.dockerfile": "8eb8efe802f2a546cfc8cd17fb66662e8df49eac3b5045c00377f9805aa85cd4",
    "assets/queries/dockerfile/zypper_install_without_version/test/positive2.dockerfile": "8a8788e045d98c30a293df5735876f7831defe3fb8fb945a60928966527ae55f",
    "assets/queries/dockerfile/zypper_install_without_version/test/positive_expected_result.json": "c6e80bcb7f164d831b24be4991e7b99b85aad8e806d2bad7d6d55afac8f4a786",
}


ZIZMOR = "zizmor"
ZIZMOR_VERSION = "1.31.1"
ZIZMOR_COMMIT = "effdb35fa7868863f11655db256d9008922fa427"  # the v1.31.1 tag
ZIZMOR_URL = "https://raw.githubusercontent.com/zizmorcore/zizmor/{commit}/{path}"
# zizmorcore/zizmor (MIT): its integration tests' insta snapshots of zizmor's own
# output, and the inputs they run on. Only the 28 audit test files that hold a
# test run as JMo runs zizmor (one input, offline, the regular persona, no
# config), and the 72 inputs those tests name, graded by
# tests/integration/test_zizmor_answer_key.py.
ZIZMOR_FILES: dict[str, str] = {
    "crates/zizmor/tests/integration/audit/adhoc_packages.rs": "aeedb20eddcd9f7b4c5f2a6ef04f847a73041a5fab293920b2328f7c3dd68838",
    "crates/zizmor/tests/integration/audit/anonymous_definition.rs": "c91b49d3ae96e7ba6e99365181de6a15c556ee9b7c94db9d106f6ffcab64fa99",
    "crates/zizmor/tests/integration/audit/archived_uses.rs": "a387cd18a42ba1bea9be247b38cc504164308f186a0a66399668b69520949aa0",
    "crates/zizmor/tests/integration/audit/artipacked.rs": "ed5eea2174dad6f0c49dbc5a19e4e93207f2316ea294ffcb2455efbc5662a8a6",
    "crates/zizmor/tests/integration/audit/bot_conditions.rs": "89636573b21f63edad4b6e3fd749196798a7dfbe17673f666ce3293821eeb8c8",
    "crates/zizmor/tests/integration/audit/cache_poisoning.rs": "2c8bd4c32529ac46cbc0542dc041717a97e167b8fba45a161fb51d14cc30877b",
    "crates/zizmor/tests/integration/audit/dependabot_cooldown.rs": "8c7ada40c76ce23d8f046d436d0bedefbc1afbb75c9de622a058f36119489f94",
    "crates/zizmor/tests/integration/audit/github_app.rs": "9cf5f406acf7690569c5ca05af39e8b6f27910bcbe878237e9b78535f639e953",
    "crates/zizmor/tests/integration/audit/github_env.rs": "1a70e9d6a0a026d2c221842b653eb8ad91fd1d17bc436628bad6c6052c0032b7",
    "crates/zizmor/tests/integration/audit/insecure_commands.rs": "5095480fd383b7ab95728232a3fff002088065c9b0ea693acd0ba6b73eb0da7a",
    "crates/zizmor/tests/integration/audit/insecure_url_scheme.rs": "b479f23dac0ec087fa86b12cde58edebe5f3dff3fd5605f00a945633c829b30c",
    "crates/zizmor/tests/integration/audit/misfeature.rs": "b1e0ee34030332688e417ec3e3717da94963a5d7f852707f857afe614a943ca8",
    "crates/zizmor/tests/integration/audit/obfuscation.rs": "2012d0d1868da947eca011bf63c08b3642e81d2950c1fc03e4fcb0eecb450c52",
    "crates/zizmor/tests/integration/audit/overprovisioned_secrets.rs": "7e86632d71674b17ac40e5d940eff7dd575632c6eec3daabab90c1c71db5ec50",
    "crates/zizmor/tests/integration/audit/secrets_inherit.rs": "7fc28199868b958f290efc7d2919205797978926f4483335e67694253c6f72a7",
    "crates/zizmor/tests/integration/audit/self_hosted_runner.rs": "ba26064e06f5d02a74bd81c210f48f63a07f6def8d72a4024591af4fb41e9bbc",
    "crates/zizmor/tests/integration/audit/self_repository.rs": "1877ea1c26e8e57ff7ca3667422f12e923f69fed9d45c1b55c6cfabc7e23d4c9",
    "crates/zizmor/tests/integration/audit/template_injection.rs": "782e28372877630c414cef847cf991f803d3a71c141026b906a725ac394a824f",
    "crates/zizmor/tests/integration/audit/typosquat_uses.rs": "862a5a20b01e5a38f82a5e4e1e86e91807c12923c969761acab5e8035fad33c7",
    "crates/zizmor/tests/integration/audit/undocumented_permissions.rs": "2576a43ea0da5bf729197d902f99d41f57c2d12fbefbb82794c925a90c8f5feb",
    "crates/zizmor/tests/integration/audit/unpinned_images.rs": "fd68a64b587742a448c79908182e5d3e6977ff05d2a0fc6012afbc07d61c81cf",
    "crates/zizmor/tests/integration/audit/unpinned_tools.rs": "ad5df455b704486828180212cadad0595dc676b8f86593c988b3ebcde843489a",
    "crates/zizmor/tests/integration/audit/unpinned_uses.rs": "aa5f2a103e46464e5d697a790a68d798d28b9deb0053709266db0cebe4c0cde6",
    "crates/zizmor/tests/integration/audit/unredacted_secrets.rs": "7b118d0f3eed637191f67c027071266ac8a49fb38f42b7c72a0c15b25e026dfa",
    "crates/zizmor/tests/integration/audit/unsound_condition.rs": "b305f186fa37215392bc9330320048f3bf46c457d80b158cda2ace0322c4dfbc",
    "crates/zizmor/tests/integration/audit/unsound_contains.rs": "a90cd2490b957761a24c39dad09a1ea18211a5c675ac53eb42e420f1fb1db4e4",
    "crates/zizmor/tests/integration/audit/unsound_ternary.rs": "8e2e111a300231570455c5ab02b9a2c338ee454d638812e5d5a720728709f65f",
    "crates/zizmor/tests/integration/audit/use_trusted_publishing.rs": "9a65a83181bd475e66db27ddf9b056b2233b3f1c450bf710455db4f4b1e86ab2",
    "crates/zizmor/tests/integration/test-data/adhoc-packages.yml": "6f3ec4b91427c61d8bf0834d081fb52f41f51ab725e68362dc16dbe99214f1ec",
    "crates/zizmor/tests/integration/test-data/anonymous-definition.yml": "e9f66a0cf3c656a438f1b2d23f8d88a3691439680108fa072a88b1bd288a1027",
    "crates/zizmor/tests/integration/test-data/archived-uses/action/action.yml": "0d73fe4dbdfce270c559ba4f3214616af72a631b2a28b3c55dc16626cfd7e1aa",
    "crates/zizmor/tests/integration/test-data/archived-uses/pre-commit/.pre-commit-config.yaml": "1b970c857cf0049204cae5af53746fb58706e54318dec77c1bac992c7141b25c",
    "crates/zizmor/tests/integration/test-data/archived-uses.yml": "651d10a200b7a179ea13f773cf4f6241ebd08d3966a6c1ba2b6b733fa35d8dec",
    "crates/zizmor/tests/integration/test-data/artipacked.yml": "12cba4f8752bfd922aae52069ab2e75b27cafc5ebffabc64e88f02b2c9048788",
    "crates/zizmor/tests/integration/test-data/bot-conditions.yml": "4fac5e99a1ff1c4c0596760f4c0148a488003bac9a165e7b43d06a7e48c0f39d",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/caching-opt-out.yml": "737ddcd41d23feeaf0162bb49638778ac117843823a79835b5b3653d1c7b746f",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-1081-repro.yml": "c610c82e473326ca350d82ea52c00b47bb2a2319b7ec161ba6a8ed63931ed03e",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-1152-repro.yml": "2499301a6ac315ebfed55e11c7c8bd35f91eeccad2d202933195bcd6ee341d8b",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-1485-repro.yml": "395c2f3cb50d1bb93b04de10ae4aaef3130747d8e6767b3dd4b5c409a3338040",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-1940-repro.yml": "fa639cc0d3f5cf8a1343310c18af606453e3d0a6427fff84c4068076cc5a3106",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-2320-repro.yml": "1de224b4421c68d3a87b085ccf9c72fb8d980a5b3050c7f393e891b7722f79a1",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-343-repro.yml": "96d9bdf91be018c26f5228d2154d87a6c860b1c5b1fce324545bfa7b20a8bd58",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-378-repro.yml": "2f66be77aa95236be95a0e9bd8c841c48a35882ee21b7e7479b5b96b787d69af",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/issue-642-repro.yml": "476f54cadb816195485a790841fb5a5afc9a369a8fe5ba6624fee6a8ce67ddf9",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/no-cache-aware-steps.yml": "6792f5e6666e5abf664febed82b40493e79712c9dd13b362d87c49f371e9558a",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/publisher-step.yml": "a4d02677af83166302d6166258b1394a8ba2a44c0c71e1b8d85d92d4495e8698",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/trigger-heuristics/tag-only.yml": "1d41a5856dc1d1818b01c9aaf305c4f58570e2e473db3fd6aa2a1529b0ab4704",
    "crates/zizmor/tests/integration/test-data/cache-poisoning/workflow-tag-trigger.yml": "f06414eb85fa9d2ef533b8cdc7621dec8be52814695803286a20306b9a955dab",
    "crates/zizmor/tests/integration/test-data/dependabot-cooldown/opentofu-no-cooldown/dependabot.yml": "30544cae85851002d843e6651d2ba69e0aa65bb0075bc1dc849bab67045f41af",
    "crates/zizmor/tests/integration/test-data/github-app/issue-2219-repro.yml": "9a21cd51ace084ff118a240c75858ea4b556e5a15235cc6025280fcef62b84e8",
    "crates/zizmor/tests/integration/test-data/github-app.yml": "064468311910c14208b986d2f3c2015a596d77cce4935b5401a41e49550c82dd",
    "crates/zizmor/tests/integration/test-data/github-env/action.yml": "0f34a3b4390934516d3eb6aa80d70c5e4fac676650dbb1be5d9a0ee83f6389cc",
    "crates/zizmor/tests/integration/test-data/github-env/github-path.yml": "481032c1cc24f0f66634cd0ae7fe343f96ad9226ae8c47471bc443f98bc2dfea",
    "crates/zizmor/tests/integration/test-data/github-env/issue-397-repro.yml": "27d011d380866c47f806b138b2947ee4dad14daab18f53721759b361c259e48e",
    "crates/zizmor/tests/integration/test-data/insecure-commands.yml": "9bfed1b1c5fabd327c12f03f7d0da2013380ad361855484938adae64a23db42f",
    "crates/zizmor/tests/integration/test-data/insecure-url-scheme/.pre-commit-config.yml": "0043cd3b5890c80ce41eac93cd98133084e7ac7153217410243115790008fe66",
    "crates/zizmor/tests/integration/test-data/misfeature/issue-1414-repro.yml": "2121d923fc0ff28b47beae535f3ddf7f51c148cf9a8180302b58cf9c90cd0b9e",
    "crates/zizmor/tests/integration/test-data/misfeature/setup-python-pip-install.yml": "8847ced94c835a8317841c2a178600144e5265213ca91bbfafed21aeeba416cf",
    "crates/zizmor/tests/integration/test-data/misfeature/workflow-cmd-default-shell.yml": "5790eb74dd6c51ef0393ee477c474bd294479f59611331a04043f5af20a75905",
    "crates/zizmor/tests/integration/test-data/obfuscation/issue-1769-repro.yml": "2ff4c31659fe271cc2b1259020e196c0e41b099245878de9b1a15aebf5cb6297",
    "crates/zizmor/tests/integration/test-data/obfuscation.yml": "d260badcec43f6a117997c21d3fe77cb603b4a22d5861334d1e57db3f6087e03",
    "crates/zizmor/tests/integration/test-data/overprovisioned-secrets.yml": "436af94f2f35fa97b5ea2c56e1031ac46a7b83f6e4b2ae2aa8b72df351d3cf82",
    "crates/zizmor/tests/integration/test-data/secrets-inherit.yml": "200506f08358c2ee9e2bd367612f372ca3f21181824c83a2af63d82bc98543bb",
    "crates/zizmor/tests/integration/test-data/self-hosted.yml": "b877013af24a29b1a1da10b29e29c8e0cdc306536c7ef86fd07716fc1a07b586",
    "crates/zizmor/tests/integration/test-data/self-repository.yml": "b22cd9385c4830655ea42aef9c01b5c208121fb60681aba38369695150efbcee",
    "crates/zizmor/tests/integration/test-data/template-injection/codeql-sinks.yml": "3de4481f02f2a1802c93add129507f3b3bdeb29b6e6bb75991c483bf1e762c6e",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-1638-repro.yml": "9a789b2cb9067f1c606cab945f1f34f86c211e4e1fb0ec93999e426f87326930",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-1802-repro.yml": "545000dbebba8bcdcf3084b52ebf0bddbec498d26acdd08f2038e9c80881f1c1",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-1903-repro.yml": "d2264cf1d9f96a774eb1224c253181b4669141407707751f647186d279a0a6d1",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-2197-repro.yml": "cd637cb3b87a1b4c8adc86a9c0617aa9c5dc9ac6c3529846189c644dc387e498",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-22-repro.yml": "afe795d45eb668538e78a1f5039e07781008e7d09d30ad7eefe881f62fee9f74",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-339-repro.yml": "c55003cac1e2fea2a462b994a8ccfe278bff61343f5ef8803464c6e6cc40ec63",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-418-repro.yml": "7de2fd552c09ad21b4b7f64da32b035074c688cb85996a40721fde61dae3e98a",
    "crates/zizmor/tests/integration/test-data/template-injection/issue-749-repro.yml": "56a9c52033fa4209e98e1824ac998c61fd2e71569c1e62560ebc5a052435cbdc",
    "crates/zizmor/tests/integration/test-data/template-injection/pr-317-repro.yml": "fbe757c7883f0c47565a8c3e9088a00d256019a5727928b5e11bc4864990cc92",
    "crates/zizmor/tests/integration/test-data/template-injection/pwsh-script.yml": "7d7809517cb54a01bdc4ecc04827ec3842693bda635d864a572c33d2e162ed64",
    "crates/zizmor/tests/integration/test-data/template-injection/static-env.yml": "d76977f50f8c600df795260ff8765883fbcb4c11e1b23bfa43328e1f0452d975",
    "crates/zizmor/tests/integration/test-data/typosquat-uses/pre-commit/.pre-commit-config.yaml": "7074c3cfa9e2c4caa19333fc5f2ca6a570613996ea49547004c2a5b6e48b353f",
    "crates/zizmor/tests/integration/test-data/typosquat-uses.yml": "172b19c75c09c13baaccd4d4d100dc8485c30bf7b8b133964c3acf17a9620920",
    "crates/zizmor/tests/integration/test-data/undocumented-permissions.yml": "e72cf2dee9b9362f3184373d7a4a5f3ddff490ed054de33924a14fdf74765b3c",
    "crates/zizmor/tests/integration/test-data/unpinned-images/issue-2097-repro.yml": "acd2d865a6634876413158a36de8a5c7db5c5d073bb2e3baad29e9f7f91aaec3",
    "crates/zizmor/tests/integration/test-data/unpinned-images/matrix-in-image.yml": "1c01a1c20ed57751650405a9c27dd595ed05feb4ae2274b6d65e55d1d1fc5b0f",
    "crates/zizmor/tests/integration/test-data/unpinned-tools/if-false.yml": "16d9bc6dcb20e8d704609c1239d3f318c0c914809172a8425f6019c9748a22fb",
    "crates/zizmor/tests/integration/test-data/unpinned-tools/setup-just.yml": "d4ecc44c3f514a424c5a2fc1a7978b1adf41df6d66bdce31b74df79cb7a3b297",
    "crates/zizmor/tests/integration/test-data/unpinned-tools.yml": "1fd87c1b7d267585f39dfa5c14c7d49efcd5e7e1cd70d96c397ac90d36bea623",
    "crates/zizmor/tests/integration/test-data/unpinned-uses/issue-1543-repro.yml": "8ad3443678f866d313c8d703082eac8758f0a8511531c2f802d3b52c03c45d1f",
    "crates/zizmor/tests/integration/test-data/unpinned-uses/menagerie-of-uses.yml": "5a0a6cb2a0075774fd055af44f535db77e34175f76a4df1f21adda1969cea0e7",
    "crates/zizmor/tests/integration/test-data/unpinned-uses/reusable-workflow-unpinned.yml": "46baa622d8e470331e9966952ec2d0e30398ad2419b34de078fe7c2626818046",
    "crates/zizmor/tests/integration/test-data/unpinned-uses.yml": "ca6b3f1ec7b63eaedcdfbfeb3ba1951a0af79af6b559aaf0d44f1bc2653e1be5",
    "crates/zizmor/tests/integration/test-data/unredacted-secrets.yml": "d5fb03b215326a4c80842c6828189b2fafc933694a78ca807fe536fa20384774",
    "crates/zizmor/tests/integration/test-data/unsound-condition.yml": "b360d22d4ff0533fc57e1eedf3f812eb6432a26d2ba04956be9da2e7a2fd3433",
    "crates/zizmor/tests/integration/test-data/unsound-contains.yml": "bdccfa2d897b72d751c7088be44627766e271ee0b388276430f7dbd7ddb0bc5b",
    "crates/zizmor/tests/integration/test-data/unsound-ternary/issue-746-repro.yml": "fabd28ba196729e528edd16bfd54e19e52f5f22b572f01654d11f7a9f9f29375",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing/bun-publish.yml": "afde2b58d7a4ab5f8e6e3b4c76d114377c037b30f529309aea443c395ed38b0b",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing/cargo-publish.yml": "80e7de786f03938b7d75a646cd8ef4ce230bf1cbf443f4cc0131460b016b090c",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing/gem-push.yml": "e5c14475277ab48becd3e23690264b5a2a06985d91646bfcdd1c6a255578cf74",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing/npm-publish.yml": "e0a1cf6f9385daafd923915c8d65c17980eb11b5535de9f537691961dc44a32a",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing/nuget-push.yml": "861fad4bf8f195630cc01fd26e8655886001d347952302ea5372a8ba00a24e12",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing/twine-upload.yml": "ed8303f3f4098ae4b7988c9878b6ef78dc32f2a22ae79d715949ab132364f146",
    "crates/zizmor/tests/integration/test-data/use-trusted-publishing.yml": "e1f88880c1444e90d8b8e976236fa13cf111f49dd738eef5f76406ce19470d9e",
}


def answer_keys_dir() -> Path:
    """`$JMO_ANSWER_KEYS_DIR`, else `~/.cache/jmo-answer-keys`; an empty
    variable is no override."""
    override = os.environ.get(ENV_VAR)
    return Path(override) if override else Path.home() / ".cache" / "jmo-answer-keys"


def sca_kitchen_sink_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/sca-kitchen-sink/<commit>`."""
    return (root or answer_keys_dir()) / SCA_KITCHEN_SINK / SCA_KITCHEN_SINK_COMMIT


def vibeproof_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/vibeproof/<commit>`."""
    return (root or answer_keys_dir()) / VIBEPROOF / VIBEPROOF_COMMIT


def kics_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/kics/<commit>`."""
    return (root or answer_keys_dir()) / KICS / KICS_COMMIT


def zizmor_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/zizmor/<commit>`."""
    return (root or answer_keys_dir()) / ZIZMOR / ZIZMOR_COMMIT


def download(url: str) -> bytes:
    """The body of `url`. The one network call here, so a test replaces it.

    It is `fetch_rule_fixture.fetch_bytes`, which asks a second time after a 5xx
    or a timeout: raw.githubusercontent.com is flaky enough to have reddened CI.
    """
    return fetch_bytes(url)


def relative_path_problem(path: str) -> str | None:
    """Why `path` may not be joined under a key's directory, or None. It names
    a file below the directory on every platform: not empty, not absolute in
    either spelling, no drive, no `..` between either kind of separator."""
    if not path:
        return "empty path"
    portable = path.replace("\\", "/")
    if portable.startswith("/") or PureWindowsPath(path).drive:
        return "absolute path"
    if ".." in portable.split("/"):
        return "`..` in path"
    return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _present(target: Path, expected: str) -> bool:
    try:
        return _sha256(target.read_bytes()) == expected
    except OSError:
        return False


def _fetch_file(dest: Path, path: str, expected: str, url: str) -> str | None:
    """Put `path` in `dest` with the hash `expected`; None on success, else why not."""
    refusal = relative_path_problem(path)
    if refusal:
        return f"{path!r}: refused, {refusal}"
    target = dest / path
    if _present(target, expected):
        return None
    try:
        data = download(url)
    except (OSError, http.client.HTTPException) as exc:  # URLError is an OSError
        return f"{path}: could not fetch {url}: {exc}"
    actual = _sha256(data)
    if actual != expected:
        return f"{path}: sha256 mismatch for {url}: expected {expected}, got {actual}"
    part = target.with_name(target.name + ".part")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(data)
        os.replace(part, target)
    except OSError as exc:
        with contextlib.suppress(OSError):
            part.unlink(missing_ok=True)
        return f"{path}: could not write {target}: {exc}"
    return None


def _fetch_pinned(
    dest: Path, commit: str, url: str, files: Mapping[str, str]
) -> list[str]:
    problems = []
    for path, expected in files.items():
        problem = _fetch_file(
            dest, path, expected, url.format(commit=commit, path=path)
        )
        if problem:
            problems.append(problem)
    return problems


def sca_kitchen_sink(root: Path | None = None) -> list[str]:
    """QuackatronHQ/sca-kitchen-sink's lockfiles at the pinned commit; the
    problems met, none when every file is in place."""
    return _fetch_pinned(
        sca_kitchen_sink_dir(root),
        SCA_KITCHEN_SINK_COMMIT,
        SCA_KITCHEN_SINK_URL,
        SCA_KITCHEN_SINK_FILES,
    )


def vibeproof(root: Path | None = None) -> list[str]:
    """humora2504/vibeproof's test fixtures at the pinned commit; the problems
    met, none when every file is in place."""
    return _fetch_pinned(
        vibeproof_dir(root), VIBEPROOF_COMMIT, VIBEPROOF_URL, VIBEPROOF_FILES
    )


def kics(root: Path | None = None) -> list[str]:
    """Checkmarx/kics's Dockerfile samples and expected lines at the pinned
    commit; the problems met, none when every file is in place."""
    return _fetch_pinned(kics_dir(root), KICS_COMMIT, KICS_URL, KICS_FILES)


def zizmor(root: Path | None = None) -> list[str]:
    """zizmor's audit tests and their inputs at the pinned tag; the problems
    met, none when every file is in place."""
    return _fetch_pinned(zizmor_dir(root), ZIZMOR_COMMIT, ZIZMOR_URL, ZIZMOR_FILES)


KEYS: dict[str, Callable[[], list[str]]] = {
    SCA_KITCHEN_SINK: sca_kitchen_sink,
    VIBEPROOF: vibeproof,
    KICS: kics,
    ZIZMOR: zizmor,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch the pinned answer keys the tests grade JMo against."
    )
    parser.add_argument(
        "keys",
        nargs="*",
        metavar="key",
        help=f"which keys (default all): {', '.join(KEYS)}",
    )
    args = parser.parse_args(argv)

    names = args.keys or list(KEYS)
    unknown = [name for name in names if name not in KEYS]
    for name in unknown:
        print(f"error: unknown key {name!r}; known: {', '.join(KEYS)}", file=sys.stderr)
    if unknown:
        return 2

    failed = False
    for name in names:
        problems = KEYS[name]()
        for problem in problems:
            print(f"error: {name}: {problem}", file=sys.stderr)
        failed = failed or bool(problems)
        if not problems:
            print(f"{name}: in place under {answer_keys_dir() / name}")
    return 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
