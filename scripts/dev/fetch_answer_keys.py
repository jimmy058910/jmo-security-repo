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
import shutil
import sys
import zipfile
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
# (`positive_expected_result.json`), and for each of its 142 Kubernetes queries
# the positive and negative samples and those lines too, graded by
# tests/integration/test_kics_line_floor.py (Phase 6, E6 and F6b). The hashes
# were measured on the blobs at the commit above.
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
    # The Kubernetes half (F6b): every query's positive and negative samples
    # and its expected lines.
    "assets/queries/k8s/always_admit_admission_control_plugin_set/test/negative1.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/always_admit_admission_control_plugin_set/test/negative2.yaml": "d37ef919ca2cc5817111befcfcce2cdd3781f57837b0adea11202c5323bcf50a",
    "assets/queries/k8s/always_admit_admission_control_plugin_set/test/positive1.yaml": "e1ef107be5f2aba2bd2bcd3c93b2aa8c78459c4a6d16ac724fa768571ce0bd7d",
    "assets/queries/k8s/always_admit_admission_control_plugin_set/test/positive_expected_result.json": "9a5ca4b238765f5131b0dda6313b5499ba6af4d336cdd7388903e95219727537",
    "assets/queries/k8s/always_pull_images_admission_control_plugin_not_set/test/negative1.yaml": "d7045fa1f9c4c0121fd22d536a0a5bfd0552ddba1f69e3c6a6cd97399d881962",
    "assets/queries/k8s/always_pull_images_admission_control_plugin_not_set/test/negative2.yaml": "2fd8ef428c511460b2fd71f82d2b30dd00f5f7f379c425a9180e15f51636b91f",
    "assets/queries/k8s/always_pull_images_admission_control_plugin_not_set/test/positive1.yaml": "75bab1424f9205083c476bba7d63886b079f103d0445fcf124b0e511cd1c7cab",
    "assets/queries/k8s/always_pull_images_admission_control_plugin_not_set/test/positive_expected_result.json": "7849409aef7cfd3a35611879361ceddc360324e82150f4b4df1da23ac61a3a41",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/negative1.yaml": "1f66bd2b0a0f6e65c2e7143031f51c3fd2bd35698de84db0b81b39fd97a1793f",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/negative2.yaml": "331021e41563e82fbbacf61003a5109d038249655a94cb29a7e114c41edf0ac0",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/negative3.yaml": "0812e7d7d694813605f7bd1e899cb480c05f400b85efc504f447d73f4e3053a0",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/negative4.yaml": "a2df6e5fce5b4a1c8db5928f0ba5b8d6383c9bc047b9798ff2d85d17c918c63e",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/negative5.yaml": "5c8dc663e3116a6a765cdd145fb7de7b2bc8cc8231d3b285ec76df715e17299a",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/negative6.json": "7c77fa46c01f8b50e4c69c5cba622eb15ca559e44e3d36fae8ea17e4a48814c0",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive1.yaml": "feab9c47dedd56521c015d0f928b898456c11475972defe16a66fdaa440ae78b",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive2.yaml": "01436fbd80a0aa788dff9dc7c4a3a9f6d43eb2eee895bb5bf859c60c8d48e4ae",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive3.yaml": "cb4c703dfb23317d0839a1e798677c450f8238a3cb67be196641b75e1d8354ff",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive4.yaml": "800731e679a693e328df8ac07a8767297d7c6a89863aed5be4e03395729b8394",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive5.yaml": "01491ffd29d3f6bc3befb4c63008f4554874cd5b9d9612ee5c51134b5fe636d9",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive6.json": "ff7d196cdfb317a688e7ada419e514f6102ba4d9501eaee224b462c545b74be4",
    "assets/queries/k8s/anonymous_auth_is_not_set_to_false/test/positive_expected_result.json": "adff98468615d2b0e8981469c6a5e0d069d5ec5074ad97c86e1bbce7ddabcf26",
    "assets/queries/k8s/audit_log_maxage_not_properly_set/test/negative1.yaml": "846035864256ee86d3d1f4a3278353a0692f386a502856e794ca3b3638a85948",
    "assets/queries/k8s/audit_log_maxage_not_properly_set/test/negative2.yaml": "acd26ceed0d6c0d9b458a9c5e8dc4e77e826c4355e4c9376bb3b535e1c498178",
    "assets/queries/k8s/audit_log_maxage_not_properly_set/test/positive1.yaml": "3de6cecf388af2c546813daaa7f1e680973e5c8fddec2bd5fabe9446ee15432e",
    "assets/queries/k8s/audit_log_maxage_not_properly_set/test/positive2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/audit_log_maxage_not_properly_set/test/positive3.yaml": "b4441a7c14710f8b27d5e9bfc9891a6ab1ce4d771b8c396dfa446da05692711c",
    "assets/queries/k8s/audit_log_maxage_not_properly_set/test/positive_expected_result.json": "02025c41a18fefcfe159f4cf8de5a4efed98f2f1de2b3e3980b30030c6f0de71",
    "assets/queries/k8s/audit_log_maxbackup_not_properly_set/test/negative1.yaml": "2ef16cc680117a54c53ef02d5f05e28e8de8a3628ca1a36643190c7d972f4577",
    "assets/queries/k8s/audit_log_maxbackup_not_properly_set/test/negative2.yaml": "7d208492ebf6c8d45b251c1769911bb10827bbd86b4fbc8da886b20cf11e2b69",
    "assets/queries/k8s/audit_log_maxbackup_not_properly_set/test/positive1.yaml": "bae90814558ed63087b166c3ab3d6f68d38e27225eaa01af7386bb4ea7736830",
    "assets/queries/k8s/audit_log_maxbackup_not_properly_set/test/positive2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/audit_log_maxbackup_not_properly_set/test/positive3.yaml": "b1ff7a522d6d75537465d15d94f57a4ec625b893552b59efef020de26c88aee4",
    "assets/queries/k8s/audit_log_maxbackup_not_properly_set/test/positive_expected_result.json": "daf4d2c223a9a46d97c8137fe9b05dfa02a7b1ea4400a267eabf7d4616910215",
    "assets/queries/k8s/audit_log_maxsize_not_properly_set/test/negative1.yaml": "a63f552e2f7e5fa2fdcb1d14b0e7fc3d335f8f61d2018dd43694ee8242c7f4cf",
    "assets/queries/k8s/audit_log_maxsize_not_properly_set/test/negative2.yaml": "986ac8f187251cc3fa718c490c5bb6622b9952b032c386095abb8d1990af2877",
    "assets/queries/k8s/audit_log_maxsize_not_properly_set/test/positive1.yaml": "12e3f6e859bae8f2ad733c31c6c18d9db16943a97c43905141271fb72c550add",
    "assets/queries/k8s/audit_log_maxsize_not_properly_set/test/positive2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/audit_log_maxsize_not_properly_set/test/positive3.yaml": "6f3e49ecfc00ac7f7c87fb2c95d6a160b4b0b57fc0d4d35a6bedbf5f2d38e703",
    "assets/queries/k8s/audit_log_maxsize_not_properly_set/test/positive_expected_result.json": "3b3fd57b94caf631f304386adeb94bf6ee804e1c8099cf2edeca7c940bf027c3",
    "assets/queries/k8s/audit_log_path_not_set/test/negative1.yaml": "89260d0339f4d2e6dc936354e4c040ac7828dbc5c09b296a2813d50ef41e0321",
    "assets/queries/k8s/audit_log_path_not_set/test/negative2.yaml": "ff635640007160d00180fc0db90626f95fa69b2440208e89374d3fc1fff07e26",
    "assets/queries/k8s/audit_log_path_not_set/test/positive1.yaml": "cbca00a73fc4d312c2e8f34958e902f229529e2dbe09327c1147dad22380047f",
    "assets/queries/k8s/audit_log_path_not_set/test/positive2.yaml": "cc8e6514c20bd88b1e0074dc4152c563b36b180a5b2c6d759ed8a66e702f3d5a",
    "assets/queries/k8s/audit_log_path_not_set/test/positive_expected_result.json": "df8c5a734085a1228c852852d65ad0a2a264a2fbadf9b59195bd37a30edd97e0",
    "assets/queries/k8s/audit_policy_file_not_defined/test/negative1.yaml": "4ea652798c62d1f1f401e54a7d948fd965907849fd96a56e1bd71b5998707e70",
    "assets/queries/k8s/audit_policy_file_not_defined/test/negative2.yaml": "e449784fa45e100b6bebcd17b473601f52dbb015a64378a09c6fa333509e33b6",
    "assets/queries/k8s/audit_policy_file_not_defined/test/positive1.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/audit_policy_file_not_defined/test/positive2.yaml": "dffe14738df8312d8a11b6fe9225b71da1fac4d6ad512d73bb624c6d96af701c",
    "assets/queries/k8s/audit_policy_file_not_defined/test/positive3.yaml": "4834a674d02b0bbfb3b9bf28b0d8c43560a9526dfc0a331b1d3385cd84cbbf08",
    "assets/queries/k8s/audit_policy_file_not_defined/test/positive_expected_result.json": "b1c3ea3ed24bb2c18c12c893d4de5787117e55f7a63dc2594d04ec7b86fe2565",
    "assets/queries/k8s/audit_policy_not_cover_key_security_concerns/test/negative1.yaml": "e14d620f7a60483f1d3ffabbfb9e2534300e35c15ccc55bf1a2d25ca45015143",
    "assets/queries/k8s/audit_policy_not_cover_key_security_concerns/test/positive1.yaml": "c5c249d0ccbb1876b2f1aabbd99447982788961ce80871e32f5f6c624c57981e",
    "assets/queries/k8s/audit_policy_not_cover_key_security_concerns/test/positive2.yaml": "9f2de96ec1fb1574b15881c01887bb00012340c1de9aff3d0a41b6fa13c6158b",
    "assets/queries/k8s/audit_policy_not_cover_key_security_concerns/test/positive3.yaml": "286d4b6f8c25fe5f4459ac9431faf29dcb9895dda94485a38786b331b49cc0a9",
    "assets/queries/k8s/audit_policy_not_cover_key_security_concerns/test/positive_expected_result.json": "6493a793581e938c495ef5426e7a8639b8e56b3039f58189a7446826d8a1e081",
    "assets/queries/k8s/authorization_mode_node_not_set/test/negative1.yaml": "cad222a66c9102e33b3bd9c6b18b8362bba0fe4e341e4274590d602d4ee330fe",
    "assets/queries/k8s/authorization_mode_node_not_set/test/negative2.yaml": "23f21a075e63cb742f44b65cc66559a1c129a6e69180264571e97ada9a4dd54a",
    "assets/queries/k8s/authorization_mode_node_not_set/test/positive1.yaml": "fb0a84cf1467ab7fa7b621759aaf27f68bc37106092e3ea487da4f5a637ef719",
    "assets/queries/k8s/authorization_mode_node_not_set/test/positive2.yaml": "6c10dc369b6af6889d468ea00c18c5963c7f0288fe876294134ca85a3694608e",
    "assets/queries/k8s/authorization_mode_node_not_set/test/positive_expected_result.json": "888092f578675033c393619ca64e30499b1785900f98ad66a4e4e427c89c6651",
    "assets/queries/k8s/authorization_mode_rbac_not_set/test/negative1.yaml": "cad222a66c9102e33b3bd9c6b18b8362bba0fe4e341e4274590d602d4ee330fe",
    "assets/queries/k8s/authorization_mode_rbac_not_set/test/negative2.yaml": "23f21a075e63cb742f44b65cc66559a1c129a6e69180264571e97ada9a4dd54a",
    "assets/queries/k8s/authorization_mode_rbac_not_set/test/positive1.yaml": "fb0a84cf1467ab7fa7b621759aaf27f68bc37106092e3ea487da4f5a637ef719",
    "assets/queries/k8s/authorization_mode_rbac_not_set/test/positive2.yaml": "36db5eddaa00bf48c890205b663f8dc4e8681ef940481596745bd46fe7c0f1be",
    "assets/queries/k8s/authorization_mode_rbac_not_set/test/positive_expected_result.json": "a3fb9b25c1b13ae0dfc522440a4d8bdc97c91e5e1b8747446d0bb5c68ef8c417",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/negative1.yaml": "5e68a656b9d634dc438476fed1c43b5107c9c81baf99ae9648b3b2d9562fe7d7",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/negative2.yaml": "f74a46c4e1b7863bfc60baf0227c6584beee8823510dbe86b3a5fd455af664c9",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/negative3.yaml": "31e72b3da8b4b30fef655b6166aa87928905eecba2bffb079b49ee9e1c7d4c6f",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/negative4.yaml": "f2b0fd62fd973a6cf14694b4c99e4fb83090654337303397914990a85e469672",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/negative5.yaml": "e3c7736e8884de7898ea391be6aae363464b7d87b0660ccdb25043de885b0812",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/negative6.json": "2542bbe89af5714d0b8d6549870bf99201da4ed4612d15df85a81f12bbd73513",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive1.yaml": "87c0245b7b42d3d118cea98c94a7290fb2653847d21557fe40ce6153c4522045",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive2.yaml": "54e00778cbd470023041400fb36b2e2920b68c4b07d602aea01053a09ef55693",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive3.yaml": "133e705f9fe696925ab254cf7d499e75d7d197c487d0dc896c9a59adccfa8015",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive4.yaml": "b3c902a16ca7457483ba63f2b909574f2bd54233007dda9f6dd59f0336a3eb05",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive5.yaml": "10122ac6a824b0cfd8a5e3b3489ad6422894fb99b62986b9e45e8abacdf24e30",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive6.json": "3d874c20a37024c430c4a394e9e94e7652b499ea33c71e44a5d3c3f5fff007c6",
    "assets/queries/k8s/authorization_mode_set_to_always_allow/test/positive_expected_result.json": "11303eb605c9bfa95b1c389e3bfa8e8ba06847e8000d1554b2e765fc2b3f01dd",
    "assets/queries/k8s/auto_tls_set_to_true/test/negative1.yaml": "372913abe8f262992d0b8dddd48379fb4fdc0dae60f6eb0888fb576ab44524ec",
    "assets/queries/k8s/auto_tls_set_to_true/test/negative2.yaml": "00278a8db3aff00dab13192ec487d0ac4a7327739f511f203e8e3e7e492d8284",
    "assets/queries/k8s/auto_tls_set_to_true/test/positive1.yaml": "951e4b7dedd4ee8cb51ab78bdad6216aba8cbf1bedac0199e11c20311728b05e",
    "assets/queries/k8s/auto_tls_set_to_true/test/positive_expected_result.json": "add35a6c8f4f0549193965cc6103a1e210acbae32513a068b73891759648f271",
    "assets/queries/k8s/basic_auth_file_is_set/test/negative1.yaml": "32b06d2350713651a90e2ff2e3dc0bb51238020404872709a3ee5f22d859ed1b",
    "assets/queries/k8s/basic_auth_file_is_set/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/basic_auth_file_is_set/test/positive1.yaml": "b8da928af8e00c3b40e189adc3960d3c3a271dc8fd29ad3aa6d5aad46283e7b1",
    "assets/queries/k8s/basic_auth_file_is_set/test/positive2.yaml": "7dcb20fe5363ee7fd78b16a6f99f616c50a0d55fad9963d0d0f0ae0477aeebf4",
    "assets/queries/k8s/basic_auth_file_is_set/test/positive_expected_result.json": "9e7d7fdc69c798a5ef5a09379f8b6af5808fa0fe3346d5919f831c80d11e7d39",
    "assets/queries/k8s/bind_address_not_properly_set/test/negative1.yaml": "cf9389c131b9ada613e4721243fdec83bb6dd9feba2fc3dd2d377a97198d24cc",
    "assets/queries/k8s/bind_address_not_properly_set/test/negative2.yaml": "a08b42c1e193dcf22d1812bf663ea951ab4228b8d301bb28a65659c925cf1036",
    "assets/queries/k8s/bind_address_not_properly_set/test/negative3.yaml": "3355be1ba349e6f937db90fdaa087d2e0af965227b28e515b26e8d029deeb524",
    "assets/queries/k8s/bind_address_not_properly_set/test/negative4.yaml": "9528c160164cef005f36c3bac56335f122dec57be4cc85bcfbe062a63f75a0a8",
    "assets/queries/k8s/bind_address_not_properly_set/test/positive1.yaml": "2aedef5a69a60e7bb3e9c2ff96d0842b4a8186c6cf196063c8fd0cf4d41e7247",
    "assets/queries/k8s/bind_address_not_properly_set/test/positive2.yaml": "76ca41e2f5633deddb28ee7498ace083ed895c05165aabb2e00f2f3da357f7ee",
    "assets/queries/k8s/bind_address_not_properly_set/test/positive3.yaml": "9af8ffccc13e8fc181b3fb46a3283c1283297effb01c80b036b82eb9e5c62176",
    "assets/queries/k8s/bind_address_not_properly_set/test/positive4.yaml": "cdfa87ff6674b6ad3c64a0cbd44a86ec7b89fe8244dfc6aa13475f6a474b4052",
    "assets/queries/k8s/bind_address_not_properly_set/test/positive_expected_result.json": "c82820fb609dbd14a8d50857e9d9419e6be6d7e9139036bf45b55397bb9f7b8d",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative1.yaml": "9def9b986ce70a3ffdc65c27bc7ff2fe8e123a02b1243e6bc1fe80c0467f1472",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative2.yaml": "952f761377f924c63aa2d8e5f64f527e4f37faf41bc1e5f8ed496decbe346dbe",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative3.yaml": "d0fe0bbe4f9e38b35836b30ea311dae46714ce0cffe64c630a111dc3f67afa2e",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative4.yaml": "555734c0ed1e9f20322ebefb68f52f6f752208a620ac4dc752fc7e9b7372469c",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative5.json": "8cc7a0ba01ab21c672d970caf96f4ff9b25222cde9bcfdd07d200fbf86c9ef3b",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative6.yaml": "092a2980ea887724733a2a9704112a8aa1ffc9e6bb147d41deb2d5280cc0c0e7",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/negative7.yaml": "f90078b784b44e99539c5903d3c7da192aab35ebc96dc8d7011ba4a5b9480e61",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive1.yaml": "fb979a0873509a0988f6e6dfcaa1623820fcdf3b75583348dd50aab0cf635e0d",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive2.yaml": "8e2b09acb17a7e5d33977d02539fd672a9dbdc0dbca65256b15e0b81f2776e6e",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive3.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive4.yaml": "90b193dded850b2da47b7e0124cc86d322422e5a9dc3413045b09b0925d2e9e3",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive5.yaml": "930c031c68207d366c2635de1939952a0b2a4e7976fad3bcbfaff5594bf2978d",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive6.yaml": "3283a1c3e376dc031192d3d6faf6aa37879e7817b3321baa990b9bcb6cd71059",
    "assets/queries/k8s/client_certificate_authentication_not_setup_properly/test/positive_expected_result.json": "b1bb01851645719704c0b3dea6828b900100055d531c00251ac8e14e34f23d2c",
    "assets/queries/k8s/cluster_admin_role_binding_with_super_user_permissions/test/negative.yaml": "72a57f6cccce68762b25249996b3cca5ee099baf5fa8dea3bb4d6ef37747f80f",
    "assets/queries/k8s/cluster_admin_role_binding_with_super_user_permissions/test/positive.yaml": "b7e18954665108469ecd74ff0bcdb4326240500a9ceb412566d52d614356968c",
    "assets/queries/k8s/cluster_admin_role_binding_with_super_user_permissions/test/positive_expected_result.json": "b3a7af3e1b688bbfaacac7e63861da94fcad799015f6fe7bd7b326ae17d12acd",
    "assets/queries/k8s/cluster_allows_unsafe_sysctls/test/negative1.yaml": "dea9f51ebe1bb87dd12399ff0f7b466d748152ed710d2701e66020bbf8f238db",
    "assets/queries/k8s/cluster_allows_unsafe_sysctls/test/negative2.yaml": "6a736b6887a701fd274f578b37e566bda1d6eb709b9d359df096f62d36eaf944",
    "assets/queries/k8s/cluster_allows_unsafe_sysctls/test/positive1.yaml": "ba6d79adbd0f68402d55b38d2fffa2f90c5b9b906f4e2330b20c8e5ed512df7d",
    "assets/queries/k8s/cluster_allows_unsafe_sysctls/test/positive2.yaml": "ab367506ffdb1f08d22b3e59ac050c7e77dc384f42897db9f0a9e5a36b63cbc2",
    "assets/queries/k8s/cluster_allows_unsafe_sysctls/test/positive_expected_result.json": "dbd1700a4da17ac9ef806079c364bbc644b018470f132f3aea64e0f4bbad6a2b",
    "assets/queries/k8s/cni_plugin_does_not_support_network_policies/test/negative.json": "b8c9cf95797420e08cee874d4348438749475c55a23bab58636e3e6a748132e9",
    "assets/queries/k8s/cni_plugin_does_not_support_network_policies/test/negative2.yaml": "e489f2b435e8f021f87c5483047c224d51566b9170137f84e04c407058cffeb9",
    "assets/queries/k8s/cni_plugin_does_not_support_network_policies/test/positive.json": "1027e19f98ea7857f8974a779a6c4aa7857e31e6b436ba8bcf49980fe504fd1f",
    "assets/queries/k8s/cni_plugin_does_not_support_network_policies/test/positive2.yaml": "f8aabb267a9f70cf31f51492c61797c9aee386da90a68d7680df82131e908a8b",
    "assets/queries/k8s/cni_plugin_does_not_support_network_policies/test/positive_expected_result.json": "ed98db86f705e77300cce6ceda23cb610cf264f1d5210b88a07460b876744abe",
    "assets/queries/k8s/container_is_privileged/test/negative.yaml": "4602961a1ddce032c327f6e03e47f4ef5a45fd4e9410901df5b1d1108bdcf681",
    "assets/queries/k8s/container_is_privileged/test/positive1.yaml": "2d46fd467ebe5f220646951e764a192ac13e5f320144e66a5ffe4fb7ac78dbd0",
    "assets/queries/k8s/container_is_privileged/test/positive2.yaml": "2ede7752292875c56a63d364ecc3ed601c2f2aa1199ec1f90de2da35919f49b4",
    "assets/queries/k8s/container_is_privileged/test/positive_expected_result.json": "eba71ae09a473021a2d26a7728f64b384187b213e7fcae15ad3608a51e9fed8d",
    "assets/queries/k8s/container_runs_unmasked/test/negative.yaml": "5575da4eff17a7bb7ea86eff9fce419599640e9a1252e6ba2aa52413db608ee3",
    "assets/queries/k8s/container_runs_unmasked/test/positive.yaml": "60832c7100bb7c907349434005460ccd88ee793d2a4550ff3602608ec4e9b695",
    "assets/queries/k8s/container_runs_unmasked/test/positive_expected_result.json": "6315d21a8a3aeea01c1d37b59a55b8c9bc1cecce8fcff86c84aa0ae6d97cb68a",
    "assets/queries/k8s/containers_run_with_low_uid/test/negative1.yaml": "0e6eef783dab34e8171740057ccce85a7fa82f7712ef464bc52e25bfd22eb6bd",
    "assets/queries/k8s/containers_run_with_low_uid/test/negative2.yaml": "a28ebd85e02f350462c7d04696dc48d65d553b53cfc05996e3dfb6713fdb1052",
    "assets/queries/k8s/containers_run_with_low_uid/test/negative3.yaml": "58b41f6e07b135c3f28d851f1e903b8f881108484ccad24628f4a4d2746de53f",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive1.yaml": "b74b15d6bf0c177023c4c8e6d55cde0253793f035e32781d0ded0428aac182cf",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive10.yaml": "7c549f24b1e55420f1be588276680e3f133a722c6a2a35fbfcf0acbbf624f149",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive2.yaml": "b0cbd80d5822b02276ed2f7267c000b7c2ad06ac5e9fa10674ca58b7ad862936",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive3.yaml": "6335f92fd0ce9614caea04eeb935c024514aee510c424c36d678906ef2b1b81b",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive4.yaml": "7b09a1c1216e2f640664f98aad589abcb0a6ddad4f6c1a65e90ab00fba6b4246",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive5.yaml": "2b00fbebbcf1c703ca6d33f74c80e4776fca61ab379d6058c95037ecd288367a",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive6.yaml": "fa59e1d1a104596384c85e41bc7fbe23f949904fa63cfb5c48d34ba9fa20a809",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive7.yaml": "440186a4012777edf4715ed12c7a596fbc485cacbc785e15cec845e157523663",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive8.yaml": "ba9ab65d0d3b8bb17bb027bb3d899fe57c57230746ccab5065f9307b9dd76843",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive9.yaml": "c35a2ce679dda6213f61787cc3bd5abe57d91d748c82d554e4790348f2316796",
    "assets/queries/k8s/containers_run_with_low_uid/test/positive_expected_result.json": "bc646e23aa544c8ee4c9523bc004ca9576f612234fe56fcdce50226539edefca",
    "assets/queries/k8s/containers_running_as_root/test/negative1.yaml": "799e0b13037ed26a2737f82e75e1cc76eac81dc08bf74c715b1a074757a6e040",
    "assets/queries/k8s/containers_running_as_root/test/negative2.yaml": "6b31db751251e56e6b34e57fdf04ba6f05cfa581fd0aee80d69058df8cfa8d45",
    "assets/queries/k8s/containers_running_as_root/test/negative3.yaml": "c202a2075ec517b1d60c090d58b55b519833c1793ec5f9a500a418c24044ca7b",
    "assets/queries/k8s/containers_running_as_root/test/negative4.yaml": "4012b457563e1997371490a8e8acbaf9f9a0be3b0c5c2e4008f08a570b015753",
    "assets/queries/k8s/containers_running_as_root/test/positive1.yaml": "3280043b5e67029d508f4206320be9d74961caba04fc5a31f8998a354eabf552",
    "assets/queries/k8s/containers_running_as_root/test/positive2.yaml": "ca75fe275af312bf47dcaa3599651129a41039014b2fce36e42a07ca3490549a",
    "assets/queries/k8s/containers_running_as_root/test/positive3.yaml": "6743c811d4d26eb0e96f05d14a8bf2440cd1a0bc21aac7e81859b326f5d565dd",
    "assets/queries/k8s/containers_running_as_root/test/positive4.yaml": "7e3a41b344a9f1b2fe0a694dda12aa5cdad41883dd6dc2c839e4672df7bb1a0f",
    "assets/queries/k8s/containers_running_as_root/test/positive5.yaml": "88c841cab505d05426c458fe581cd840f7cab990fbc9e7fb065e4f9791238f52",
    "assets/queries/k8s/containers_running_as_root/test/positive6.yaml": "ed03b21e115cd3a71fca9b672ad376feac083ff1224045f55870f777ce774108",
    "assets/queries/k8s/containers_running_as_root/test/positive7.yaml": "7c549f24b1e55420f1be588276680e3f133a722c6a2a35fbfcf0acbbf624f149",
    "assets/queries/k8s/containers_running_as_root/test/positive_expected_result.json": "70b860b0b336e9158e42c3136c3b3effac08a89ac27b5aedaa30e90a66ae78fd",
    "assets/queries/k8s/containers_with_added_capabilities/test/negative1.yaml": "6b36657c9731fd0df2316fe7f8492ee44bf70df51cf17a1a1d7460e5813a2fd5",
    "assets/queries/k8s/containers_with_added_capabilities/test/negative2.yaml": "f036a55c104271ff03701ad2d2df69d48ed2d5435dd94bc7adfeaf29a140e93f",
    "assets/queries/k8s/containers_with_added_capabilities/test/positive.yaml": "44b7e6bb06d35bc0bdce96adc331555e4c0ff3c59a8e2c6979674fa85b62c306",
    "assets/queries/k8s/containers_with_added_capabilities/test/positive_expected_result.json": "ef635c96c761962059e5d5b544492844264a11da2bacef3c363f4d14af268772",
    "assets/queries/k8s/containers_with_sys_admin_capabilities/test/negative.yaml": "6b36657c9731fd0df2316fe7f8492ee44bf70df51cf17a1a1d7460e5813a2fd5",
    "assets/queries/k8s/containers_with_sys_admin_capabilities/test/positive.yaml": "28b58fc7e3c5e5942ad5baf0f28ba385f7d4483dffa292a094a7944eb8709079",
    "assets/queries/k8s/containers_with_sys_admin_capabilities/test/positive_expected_result.json": "00e40f6920eeec1815663c36aaff4a2ff4420861d000fd7e8445b981ae202f22",
    "assets/queries/k8s/cpu_limits_not_set/test/negative.yaml": "a2b8868a71e37031c6b95c6fa0755055cfee176147fc3ce8ce81ac313a06e780",
    "assets/queries/k8s/cpu_limits_not_set/test/positive.yaml": "8aa135d5f0a6297165590df381dbe91788b35e73099b3e8e7bd70978ed5c2820",
    "assets/queries/k8s/cpu_limits_not_set/test/positive_expected_result.json": "53909710f659fc3967392ecde37726c034d4363bd56a9452394ddcdd678eaed9",
    "assets/queries/k8s/cpu_requests_not_set/test/negative.yaml": "bf1624135859a75cfcfb132b9179b4729c89d360e6f8460afbeca78b88ee08a0",
    "assets/queries/k8s/cpu_requests_not_set/test/positive.yaml": "e0462f3eb78537652e39286a0d8218f2b678a04cdbb0df6e8199f85cc31e253e",
    "assets/queries/k8s/cpu_requests_not_set/test/positive_expected_result.json": "df22ff91c792d340b0266cdebd6973c6d5c8f9f21d1e7de66ca9851841acfe88",
    "assets/queries/k8s/cronjob_deadline_not_configured/test/negative.yaml": "e754f2263a5fb7155f63c8c2cd1947df81cdc202e94cbdf942666ff874fe7901",
    "assets/queries/k8s/cronjob_deadline_not_configured/test/positive.yaml": "bf627869bbd4cc6390bbf40de3ed8dc1410fc1a9bed958804a724f2c51ba5a91",
    "assets/queries/k8s/cronjob_deadline_not_configured/test/positive_expected_result.json": "8e3e2a20b1facf6825c2189d4488a8232a660fd00476ecf6e31d63d37cd6c63c",
    "assets/queries/k8s/dashboard_is_enabled/test/negative.yaml": "57bbcb70a25e8b82bc8d37e85dddfaa0c36d53a0161d8f828367adc424b382a2",
    "assets/queries/k8s/dashboard_is_enabled/test/positive.yaml": "771b70651b3e510f4689f2d3eb7d8ae23c2b91d3ab0e8f2ed6315b05be2b99f3",
    "assets/queries/k8s/dashboard_is_enabled/test/positive_expected_result.json": "4b2dad3b5360e83690e5d03da2576cbd131a9d7d6a7a0a8ed1e8e4699dda80fb",
    "assets/queries/k8s/deployment_has_no_pod_anti_affinity/test/negative.yaml": "105d05dc540b77ad22ac8ea8d81ede5b84300cfedfcf6ccab9957e55fc3fbb7a",
    "assets/queries/k8s/deployment_has_no_pod_anti_affinity/test/positive.yaml": "eac562a5513feb9cb84e901e43a4457f43fbb7df610eb6b040447fbc43272a39",
    "assets/queries/k8s/deployment_has_no_pod_anti_affinity/test/positive_expected_result.json": "de59999c71e2a9364b54d6196184e045f7c68a8cb93ad8101b6a2f6e8a12bdd7",
    "assets/queries/k8s/deployment_without_pod_disruption_budget/test/negative.yaml": "61ef9ec5ffdb7a663900579d282784d91ec317fbae08d8f1cc6a6a1a1b2bc118",
    "assets/queries/k8s/deployment_without_pod_disruption_budget/test/positive.yaml": "8d75c996b61b6706ad437da35f2962cc83ababdac9237b94eaa2df4ca7d1b7cc",
    "assets/queries/k8s/deployment_without_pod_disruption_budget/test/positive_expected_result.json": "1234acb0834aaec67c8a7f31d06c4547498bbd411cea58ab408f9bcebe5a2495",
    "assets/queries/k8s/docker_daemon_socket_is_exposed_to_containers/test/negative.yaml": "9b26c49421bba3cf8b5b9de57d7ebf45551b7077e62d15798662d01c58f3d93a",
    "assets/queries/k8s/docker_daemon_socket_is_exposed_to_containers/test/positive.yaml": "3d0515feb67d4e566d4164730f853e7373d5b16b842b617d16ceb99df09aba29",
    "assets/queries/k8s/docker_daemon_socket_is_exposed_to_containers/test/positive_expected_result.json": "e81f404219f9a74e7d813fdeecf2605613a2868d38a48be4a4b98a11338bdc41",
    "assets/queries/k8s/encryption_provider_config_is_not_defined/test/negative1.yaml": "73f8c193d1aff6063ed97e319b61c7524d3401b33f998c6a9a17a449eaf2646f",
    "assets/queries/k8s/encryption_provider_config_is_not_defined/test/negative2.yaml": "e7914420dc8c875effc7db19d0faf74d0ed56dc715eb2babd3dfc9660c3c982e",
    "assets/queries/k8s/encryption_provider_config_is_not_defined/test/positive1.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/encryption_provider_config_is_not_defined/test/positive_expected_result.json": "8c3e34108df539da0a93659ee827670d30337e700f2dc25d98ae4d12dc7a202e",
    "assets/queries/k8s/encryption_provider_not_properly_configured/test/negative1.yaml": "835c97dc7a44a7868b34b3712a4681f8017bd1c681b2dfbc7b665e9795a9aa0d",
    "assets/queries/k8s/encryption_provider_not_properly_configured/test/positive1.yaml": "f3fbe088443efed9ba3d2d96ba0d3a63e947350b0aa7c947eb0ffc13e941231c",
    "assets/queries/k8s/encryption_provider_not_properly_configured/test/positive_expected_result.json": "445161504eb12a583532e9147de465a7d1db4ea6c1654d9a008d12c9d01ba159",
    "assets/queries/k8s/ensure_administrative_boundaries_between_resources/test/negative.yaml": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "assets/queries/k8s/ensure_administrative_boundaries_between_resources/test/positive.yaml": "6612fdb6eecd812201e5616372d2a3add2462fdc6757cea1a8a58fff1a394b95",
    "assets/queries/k8s/ensure_administrative_boundaries_between_resources/test/positive_expected_result.json": "0f69c7204ed96cc03c5af9b220d7917d28f1bdac515b11debc25ca9215d28fe1",
    "assets/queries/k8s/etcd_client_certificate_authentication_set_to_false/test/negative1.yaml": "8c73b15b546350abd05438b851351a06ac92198b06b41817c1f9ab5bbde310a7",
    "assets/queries/k8s/etcd_client_certificate_authentication_set_to_false/test/positive1.yaml": "17561599fbae33946d1bbecf8b8acd268aafb58b6f7098678b8ce2b58855bd69",
    "assets/queries/k8s/etcd_client_certificate_authentication_set_to_false/test/positive2.yaml": "372913abe8f262992d0b8dddd48379fb4fdc0dae60f6eb0888fb576ab44524ec",
    "assets/queries/k8s/etcd_client_certificate_authentication_set_to_false/test/positive_expected_result.json": "ebe944bcfe9a4eaf6230e74b86aef78ab68c6ab38340bb05f5ddce28c6c54dc6",
    "assets/queries/k8s/etcd_client_certificate_file_not_defined/test/negative1.yaml": "a0fec8fabd23ea52283238fb000b05fd1f9f5be8f6493058928ebccad9b89c18",
    "assets/queries/k8s/etcd_client_certificate_file_not_defined/test/negative2.yaml": "1348a24e656102e3c2b994a907523ac839e72670364f607effcaca3c8eafe9a1",
    "assets/queries/k8s/etcd_client_certificate_file_not_defined/test/positive1.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/etcd_client_certificate_file_not_defined/test/positive_expected_result.json": "45b1c34c08109b8d0d08480a72cc46c238c018f9f204b4731ff25e0064340c86",
    "assets/queries/k8s/etcd_peer_client_certificate_authentication_set_to_false/test/negative1.yaml": "8274e99dbf21fd4814984b4203d31f9f121959da8941e209e57c8507eaecde7d",
    "assets/queries/k8s/etcd_peer_client_certificate_authentication_set_to_false/test/positive1.yaml": "cb0e308113adfa9da41a6503467216ad96f7c0639d79a2d93bdb8f64ead857bb",
    "assets/queries/k8s/etcd_peer_client_certificate_authentication_set_to_false/test/positive2.yaml": "372913abe8f262992d0b8dddd48379fb4fdc0dae60f6eb0888fb576ab44524ec",
    "assets/queries/k8s/etcd_peer_client_certificate_authentication_set_to_false/test/positive_expected_result.json": "a453787687ba4a4845d667e26312ef54bbc8157ba42f03df83c8898b90243291",
    "assets/queries/k8s/etcd_peer_tls_certificate_files_not_properly_set/test/negative1.yaml": "9c503081de13938f4392e7409d68d7fcf09140ddf275395acb38a5713ee2059a",
    "assets/queries/k8s/etcd_peer_tls_certificate_files_not_properly_set/test/negative2.yaml": "ca6362c640f5770d9ec3b935dd3b6303edfc584fcecb73e6abe8f1fe408ef1cb",
    "assets/queries/k8s/etcd_peer_tls_certificate_files_not_properly_set/test/positive1.yaml": "71cf35431c93c6a1f8e376d544e3e4ba56a1fa31d9e6b647bdaf3bfcf09eb499",
    "assets/queries/k8s/etcd_peer_tls_certificate_files_not_properly_set/test/positive2.yaml": "06173851e2717cb44826a183eafabd8a45877013ddf9c44ec476c0595ad209be",
    "assets/queries/k8s/etcd_peer_tls_certificate_files_not_properly_set/test/positive_expected_result.json": "c5ddc0eb261ba18641d768ba71dfd98eba1ed68f6f08e3a01a6a9a30e13be34c",
    "assets/queries/k8s/etcd_tls_certificate_files_not_properly_set/test/negative1.yaml": "6d37a4904e0ac8a86b24f97b70b6ef249fc130e9d0a162e71d4c94b3e4faa27a",
    "assets/queries/k8s/etcd_tls_certificate_files_not_properly_set/test/negative2.yaml": "c416ee61181ac0a96ea045ace22638cd8ca2ef8e58f239a490aed9b8415779f5",
    "assets/queries/k8s/etcd_tls_certificate_files_not_properly_set/test/positive1.yaml": "325d5e1668f98e9b8048ec23bbba36d7f8db1ac59f9c59ca7c129566c6498a21",
    "assets/queries/k8s/etcd_tls_certificate_files_not_properly_set/test/positive2.yaml": "d1aeb1f14edcb6fdb53de2e30e7badbe691d4bbc0b9bc0dd18a42c92c69b05b2",
    "assets/queries/k8s/etcd_tls_certificate_files_not_properly_set/test/positive_expected_result.json": "6389a7339fc1beb33601dc479ef2c79f44272bd4293ca75ed8e9a0a2c7b41b02",
    "assets/queries/k8s/etcd_tls_certificate_not_properly_configured/test/negative1.yaml": "404ad56e702ed905368394e88bff655d5b56fa3748ae7b539d72915b8389176b",
    "assets/queries/k8s/etcd_tls_certificate_not_properly_configured/test/negative2.yaml": "b522e1528c132daaedcf4c1e80c3b8dd46abe2a04340c259218e1518baea4c31",
    "assets/queries/k8s/etcd_tls_certificate_not_properly_configured/test/positive1.yaml": "53a74b11963772c9b892c9638f1d5655364f528b5b42c24e8dd7a722b69b2f2f",
    "assets/queries/k8s/etcd_tls_certificate_not_properly_configured/test/positive2.yaml": "0ddc0cad8eaeb0f6f5ea41eb01e9cf7b848eeca118b3f9aeda73025c724c9cd0",
    "assets/queries/k8s/etcd_tls_certificate_not_properly_configured/test/positive_expected_result.json": "ad6320d38ada7ae791f1dfbf860a3c74751bf220bc983969cfeea2aa2ea2eb71",
    "assets/queries/k8s/event_rate_limit_admission_control_plugin_not_set/test/negative1.yaml": "fc7a4313ab723690b59d3c0054e5c969381140f076800c57310705ad50a13e17",
    "assets/queries/k8s/event_rate_limit_admission_control_plugin_not_set/test/negative2.yaml": "d37ef919ca2cc5817111befcfcce2cdd3781f57837b0adea11202c5323bcf50a",
    "assets/queries/k8s/event_rate_limit_admission_control_plugin_not_set/test/positive1.yaml": "75bab1424f9205083c476bba7d63886b079f103d0445fcf124b0e511cd1c7cab",
    "assets/queries/k8s/event_rate_limit_admission_control_plugin_not_set/test/positive_expected_result.json": "fd6308572a948f936590e26c9bb15d7d3964c6048c744b60d10c335acf058f0a",
    "assets/queries/k8s/hpa_targeted_deployments_with_configured_replica_count/test/negative.yaml": "0889d2b592e02c2a60c0096cb7fefed86f51fbdf087fd79e206def45830a12e3",
    "assets/queries/k8s/hpa_targeted_deployments_with_configured_replica_count/test/positive.yaml": "118315f34800234a0f204a30a6021cca569d8dd6a7e66607cd70f1b420b24660",
    "assets/queries/k8s/hpa_targeted_deployments_with_configured_replica_count/test/positive_expected_result.json": "21256125c0a27d91334a7aa8eebac6255be7f73fb545eb56613efe61f78e4a09",
    "assets/queries/k8s/hpa_targets_invalid_object/test/negative1.yaml": "557b4805b70d7b4cc8d9c8abdeff6f8f0faf2bb64558c91ed260938de0326a0d",
    "assets/queries/k8s/hpa_targets_invalid_object/test/negative2.yaml": "c30226eaa75b05711b36a40e5d68c191bef3d2a3633ac433be679a107d7cd54d",
    "assets/queries/k8s/hpa_targets_invalid_object/test/positive.yaml": "9c74b04ae834ba4656b60bc47da6a15e8a94f4840e7745a425f7832901365144",
    "assets/queries/k8s/hpa_targets_invalid_object/test/positive_expected_result.json": "dd5ff02a581471210edd319a6919ce6828e7d94f936c3899dbc484c45b8bf533",
    "assets/queries/k8s/image_policy_webhook_admission_control_plugin_not_set/test/negative1.yaml": "c1a1a1a88c753b8d70a1580be62b932aefb7cfa906f7781f5e2f66f66e5b54d6",
    "assets/queries/k8s/image_policy_webhook_admission_control_plugin_not_set/test/negative2.yaml": "6ffa657b9d69fdfdbfeae3bf63c514b4b304ac8df2cbac72946180f20232738d",
    "assets/queries/k8s/image_policy_webhook_admission_control_plugin_not_set/test/positive1.yaml": "75bab1424f9205083c476bba7d63886b079f103d0445fcf124b0e511cd1c7cab",
    "assets/queries/k8s/image_policy_webhook_admission_control_plugin_not_set/test/positive_expected_result.json": "ee57e85565e384722fe3928539f5b1a4dde52359bc313dd3fe32159418567add",
    "assets/queries/k8s/image_pull_policy_of_container_is_not_always/test/negative.yaml": "cdab8e5d262e786ebc9770ad46360ec99b3e570d1767706ea9ec755b75963835",
    "assets/queries/k8s/image_pull_policy_of_container_is_not_always/test/positive1.yaml": "3174f1fbdd474e19181ab9c8873344e6ebda3c077b0c02984954abd6a897bbff",
    "assets/queries/k8s/image_pull_policy_of_container_is_not_always/test/positive2.yaml": "7159e6a70f0a84582098f607a02534a4b77efd43a82eeefba3d8c55177381644",
    "assets/queries/k8s/image_pull_policy_of_container_is_not_always/test/positive3.yaml": "464187c942094d3522d4aa6a82ee09f3c924ca1be8fb3ee0f12839b07794b6ae",
    "assets/queries/k8s/image_pull_policy_of_container_is_not_always/test/positive_expected_result.json": "0d575b2b74f9e239189354d9291eed7fd0b5c899d7051275497ce14b7c7f8ea8",
    "assets/queries/k8s/image_without_digest/test/negative.yaml": "29bed5839f8a0ab565952bee97c4e9ff20555550b9f319af85d60595ae6e186d",
    "assets/queries/k8s/image_without_digest/test/positive.yaml": "f826f7775ad028b18dd6a2791145c259978c66d8ca49c0cfe98fb65b6758144b",
    "assets/queries/k8s/image_without_digest/test/positive_expected_result.json": "46cc03082f47e30fa5d1a36942fdb4ccd45fa8fec0dd31f01b03ffdbcb742828",
    "assets/queries/k8s/incorrect_volume_claim_access_mode_read_write_once/test/negative.yaml": "e74abe34a79a2666263237035812bf26547b7dd2f70a1071b2474441e2fa1a17",
    "assets/queries/k8s/incorrect_volume_claim_access_mode_read_write_once/test/positive.yaml": "2348deb7de873325c90f554a97ba0751587c544575d8294235ed603aef5ebda5",
    "assets/queries/k8s/incorrect_volume_claim_access_mode_read_write_once/test/positive_expected_result.json": "7d51c6fee11f685d8b1b8d2892d1bf514bdf49d6bf4e12bf4fff17bfc8330e0e",
    "assets/queries/k8s/ingress_controller_exposes_workload/test/negative.yaml": "39275832f13f05774abc8f3d91f498e08f1c28966991473ae06d0f4ed93369e3",
    "assets/queries/k8s/ingress_controller_exposes_workload/test/positive.yaml": "542e54469dfabbbc809bbe4c73a6c0511b4b595c8b91dc1ca7d32317bd775bba",
    "assets/queries/k8s/ingress_controller_exposes_workload/test/positive_expected_result.json": "8562d190c883426f698fab34b6cb29d4b2ac36371e6f5c44ce4a91dc213f4acc",
    "assets/queries/k8s/insecure_bind_address_set/test/negative1.yaml": "32b06d2350713651a90e2ff2e3dc0bb51238020404872709a3ee5f22d859ed1b",
    "assets/queries/k8s/insecure_bind_address_set/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/insecure_bind_address_set/test/positive1.yaml": "b2c81b8a4438f25302dcf3ff0126e26f68d6047aca5e653994e76722a2d004ed",
    "assets/queries/k8s/insecure_bind_address_set/test/positive2.yaml": "31f6762f41d1ddc97cae6d1868376585c5ce2deb01dcc62f7931744b9132d512",
    "assets/queries/k8s/insecure_bind_address_set/test/positive_expected_result.json": "1c55d9243c2891fd24b36180436bd23277a70ae76d5582b5512c1699a50abec0",
    "assets/queries/k8s/insecure_port_not_properly_set/test/negative1.yaml": "d43c548d1f2ecef23df88b862edfb3220726d5d37e58e50c11f39b7e236e49b8",
    "assets/queries/k8s/insecure_port_not_properly_set/test/negative2.yaml": "3f2f14f196bb2c99f5cf8a78f8145eb6287f40f816f3e7dfa38acc41caf975f1",
    "assets/queries/k8s/insecure_port_not_properly_set/test/positive1.yaml": "054c5afb09aa8175609e20b6620e536ef63f629f8f9218118d196a6d25b13af6",
    "assets/queries/k8s/insecure_port_not_properly_set/test/positive2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/insecure_port_not_properly_set/test/positive_expected_result.json": "dd134a198cc561fd3bff5f62f0e225a9b321d5521c414c59534ddc849cdf4c92",
    "assets/queries/k8s/invalid_image/test/negative.yaml": "0a273c48a340b97f8c2090d6b0a15cf2b9a852c388ab1d04ede3464b3f69a684",
    "assets/queries/k8s/invalid_image/test/positive.yaml": "fa1df8eb249debfc1ad7bbde5693bbaff39c668d92d14f5dbfd2cf57e303014c",
    "assets/queries/k8s/invalid_image/test/positive_expected_result.json": "0cc41031571047d210a5964cf4386b67731ec30bf4cc61bb9cb8618e7919f350",
    "assets/queries/k8s/kubelet_certificate_authority_not_set/test/negative1.yaml": "24fe23ede2d71ed81ac90aad3d7440d7a98cc3b638fa8a4f90bf7a77645536a1",
    "assets/queries/k8s/kubelet_certificate_authority_not_set/test/negative2.yaml": "f2e8b6cf47bb06c1f8c82de4c4307b4596eb3c35bf32a5b162428bd1b13b6186",
    "assets/queries/k8s/kubelet_certificate_authority_not_set/test/positive1.yaml": "32b06d2350713651a90e2ff2e3dc0bb51238020404872709a3ee5f22d859ed1b",
    "assets/queries/k8s/kubelet_certificate_authority_not_set/test/positive_expected_result.json": "1edcbfae9e92e723009b938e45f93deeab93022c17c4f2c7a31d7d5e8aac13b6",
    "assets/queries/k8s/kubelet_client_certificate_or_key_not_set/test/negative1.yaml": "259ef181ff2f3f9982c180b6a082795f70329f665d567704b08b94b8749df78f",
    "assets/queries/k8s/kubelet_client_certificate_or_key_not_set/test/negative2.yaml": "2bfeec165e53f1fc5ded9abe6e903326c8a1d82aa7ffb90b0d895873ee6a69c3",
    "assets/queries/k8s/kubelet_client_certificate_or_key_not_set/test/positive1.yaml": "32b06d2350713651a90e2ff2e3dc0bb51238020404872709a3ee5f22d859ed1b",
    "assets/queries/k8s/kubelet_client_certificate_or_key_not_set/test/positive2.yaml": "625aa0220c86459388968f803147dbc6c59f06a0ebb8b5206d819e8dd0240dc6",
    "assets/queries/k8s/kubelet_client_certificate_or_key_not_set/test/positive3.yaml": "2b7b257f5d1f8334cc9e4ef97f0b8bf872cbd8cc3978f0542e62e14078d6049b",
    "assets/queries/k8s/kubelet_client_certificate_or_key_not_set/test/positive_expected_result.json": "81d215bf120b0ca0406a143e5f6d0807b96ed0be89e1be35af26408272f6ade1",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/negative1.yaml": "b5f6b282e53e119cd4439fb06d029db189f8da0ea6c094d115d29bdb657f74e2",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/negative2.yaml": "373f96ed9e38e532c91a7b10a07fa1de0e4b93959a7cc9ab1ec7f3a1ae1b2200",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/negative3.json": "5c54b7c619b9b49e2ac243cbd664220edfa56d4b7d98373293bdf2b9387bf3d4",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/positive1.yaml": "9c8de092e4d11260d9b4019296ceaa9194ab4d2a98f74572c08e915ff4b81c0a",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/positive2.yaml": "0dc5d06323774b7fae8ba3e1fcd93b6c90cd1dee03442fc8da7c5dbedc41565e",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/positive3.json": "5c6aa477984edf9dd81c4272fec1fcd9d5e3dd360f06a4d7c4c37d0fa09c4a1d",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/positive4.yaml": "ac6cf4a1a87b7899225c5d2f0049ea37d48dc6155484b64750e0ccbfbdff4f2f",
    "assets/queries/k8s/kubelet_client_periodic_certificate_switch_disabled/test/positive_expected_result.json": "9cf7606be04dd56c73bb69fa01528787d9b253f76a9f2f7dce2c4a5cfaba4e01",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/negative1.yaml": "638490041b12fb6c0684baaec08c59e2d0188e16919da68605f67e26e856bd3a",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/negative2.yaml": "952f761377f924c63aa2d8e5f64f527e4f37faf41bc1e5f8ed496decbe346dbe",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/negative3.yaml": "0f8ed5e7eec7269714b4c6ed4db4c063b9c333d07684b089db2262b8564f192c",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/negative4.json": "ba6c25835853abcdb03b30fe320f02b82036e9ff1d25680bc2c20a08a6724243",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/positive1.yaml": "84dcc70b94c6fc991450292ea43e462e113ebb137f2cf879f601107ce9c374d2",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/positive2.yaml": "dd9b5d7d6f1528bc6bb0cf329a57e6355c077c1e12931312a0a81c3630621c6d",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/positive3.yaml": "0211885e30196fb5aac6a6a830b240678dbda238eb9398c6c979889a066495c1",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/positive4.yaml": "d9ef650f2e3497bf06355050ec79acf15d1ccc0f79a7c26bf39208ffd131221b",
    "assets/queries/k8s/kubelet_event_qps_not_properly_set/test/positive_expected_result.json": "e3e49dc878c27b6ce38ca38c4442402e925b7e213e9bf49de47419390a7ea8e1",
    "assets/queries/k8s/kubelet_hostname_override_is_set/test/negative1.yaml": "952f761377f924c63aa2d8e5f64f527e4f37faf41bc1e5f8ed496decbe346dbe",
    "assets/queries/k8s/kubelet_hostname_override_is_set/test/positive1.yaml": "41a2bcb19de1de381fd59e29b01e3e681e6ab61da88c17203828cfd13f79d8e5",
    "assets/queries/k8s/kubelet_hostname_override_is_set/test/positive2.yaml": "a823a2182ca0e91025dec050b47b0a2c5321477ccd3808128ff4bfc2247ebb01",
    "assets/queries/k8s/kubelet_hostname_override_is_set/test/positive_expected_result.json": "719b28fc7a5f5cd5caecc6fed6c3265f2d479d4b03602aee390341ba0bf7915d",
    "assets/queries/k8s/kubelet_https_set_to_false/test/negative1.yaml": "32b06d2350713651a90e2ff2e3dc0bb51238020404872709a3ee5f22d859ed1b",
    "assets/queries/k8s/kubelet_https_set_to_false/test/negative2.yaml": "6c43ae829265d61393c3eeb8bbfaff47ccd971e6a8506591ecd853e1b7b6fba8",
    "assets/queries/k8s/kubelet_https_set_to_false/test/positive1.yaml": "f31f7ab1cbbaf7bda5fc0611cb5e813d892f08944d213fa0df253c3d8732a012",
    "assets/queries/k8s/kubelet_https_set_to_false/test/positive_expected_result.json": "d1bbed6201c27ae02e0eef4a7bb45db232dae4d0933244198d3536686d12a504",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/negative1.yaml": "1b12f6c0b5ddb015a39f7ae25af594fa1c18ae424e85dbf3031c7917d41800db",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/negative2.yaml": "4692322aaa894821d79c8e37cfd18e774f597f67d318dd7151e4605a0c651bda",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/negative3.yaml": "ac6cf4a1a87b7899225c5d2f0049ea37d48dc6155484b64750e0ccbfbdff4f2f",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/negative4.yaml": "6ee5c2411c6f91fd1d15d072f596cb180466f19ec391d3570306bf5515e37e38",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/negative5.json": "a2fefccc3b622ffdbea6cd2302f9c66939e5e9c7bfad89fa13ab7faa6eaf5d3d",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/positive1.yaml": "a4e5bca190c561819e40b5aa7b0af82d6df9a5e4f714320d09ae7034c3ee633a",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/positive2.yaml": "1a72aa1141c8cd33ddce05fa6b1986161789c200870f42086213e7a0aee969d6",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/positive3.json": "ff074dd65c8f74b39179cc1e86d1d07d6aa6e27d7f37debfa8886feea81e2a80",
    "assets/queries/k8s/kubelet_not_managing_ip_tables/test/positive_expected_result.json": "507d69a34db5107851268b3d443fd8d2bdbc223b8d1ff1cfd0c275cf3f14fcfa",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/negative1.yaml": "4123a888d4e4494d88d8bbf8dabdebd1e6c9feeae8fccfa67d76cac51c872910",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/negative2.yaml": "952f761377f924c63aa2d8e5f64f527e4f37faf41bc1e5f8ed496decbe346dbe",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/negative3.yaml": "9acda6affd6f92ce4d1f3a33fe510c1a9b0f74e471c40f02d3d6a81402d28075",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/negative4.json": "c9048305fa4496a2009b64077d2ee3fef9dbfd9895426cb14a942482ef19cf3f",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/positive1.yaml": "a23acaa137592afbf96907d50029e3a6331dbe7ce895d044e849ca7dee7ce30c",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/positive2.yaml": "a84524eb398f45ad69906b011cb559dc16cc79d88099b9b9fe2ce73efea3791a",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/positive3.yaml": "d3005d840de7d86b654b6b75e67bf9bb5c6cba9c0981dc534102ca30ff21fecc",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/positive4.yaml": "d9ef650f2e3497bf06355050ec79acf15d1ccc0f79a7c26bf39208ffd131221b",
    "assets/queries/k8s/kubelet_protect_kernel_defaults_set_to_false/test/positive_expected_result.json": "e20310b9b1b0f9045009445ad526340d06639bdb5051098b8d0d9f9fc7c74d57",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/negative1.yaml": "60f7178bb73631b8130fe1e7aa7da9c93ac8092faab596b701aecbb6cb50ea76",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/negative2.yaml": "9f211b6039988568623e7b81a9a7ce94953544352e85d2f4066dc8b4d782e9b1",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/negative3.yaml": "cf3b028758996d5eedd1996bfcf55ecb6286ce51d73cbcd973f3254b75b41f53",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/negative4.json": "b5406ce2a84c7bdb5ca1f3d0c02ee6d29934dce50a5c462a2d883d5338e6caa1",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/negative5.json": "533f614a272ad14d6c3956eac1d110e212ad4499e7aa8a5faf3b4b39db38ca95",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/positive1.yaml": "a5e33a0a32e4ac67d4e6b83f70ca8d89b7490cb5bb29ae094b3abe914a77b984",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/positive2.yaml": "0882ec9fee359be576b8255c22ad84920d642d99e0e3397000dca8417da31966",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/positive3.yaml": "810e26433bb30e8d309e04be12ee77f50ddb3b79ba3f30fa1c8ffb31e5e860ea",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/positive4.json": "3ae608d9b7ffbc3551c3ed0d1c5a4b285ff1e04ecd6f462fdcb1bd0fe9f43a8c",
    "assets/queries/k8s/kubelet_read_only_port_is_not_set_to_zero/test/positive_expected_result.json": "69c82a84f9bb8fa4566fc1a074083a4d4ce5983ea0d971710b85da52eaed6fb2",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/negative1.yaml": "6ee5c2411c6f91fd1d15d072f596cb180466f19ec391d3570306bf5515e37e38",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/negative2.yaml": "ac6cf4a1a87b7899225c5d2f0049ea37d48dc6155484b64750e0ccbfbdff4f2f",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/negative3.json": "d0e9f8113c7fbefe57895fa749ffb5c3f85de6a1712566f20f91ad89470f015c",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/positive1.yaml": "79883c1980be958fecc6e25a9aa6ad7cdb3eae2a825737db13a66acd0e193fdb",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/positive2.yaml": "58489abf7b95747b70cc85ffed0317605ef0c93cbc1e955dafdc417eaad7bcda",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/positive3.json": "5e3a922dd9dbed3a51d90e9f160c67f7685fe80951cb765167026e3ae18d880d",
    "assets/queries/k8s/kubelet_streaming_connection_timeout_disabled/test/positive_expected_result.json": "841d0ab231c9258ac732240619e8a547f3da59360b3a1436633de72d6d918057",
    "assets/queries/k8s/liveness_probe_is_not_defined/test/negative.yaml": "32ca6c75db5dd3aac64d35e727f1c12b3f17aa2b6b452986d5f7c23c40368d58",
    "assets/queries/k8s/liveness_probe_is_not_defined/test/positive.yaml": "da18327536c69584ad4baab387cda3d070401ab795f98a6b2e694dda07d22e7b",
    "assets/queries/k8s/liveness_probe_is_not_defined/test/positive_expected_result.json": "6c3b2d9429e933ec13b87b639b0055551ea438d49b27a5b09c38996f35e91379",
    "assets/queries/k8s/memory_limits_not_defined/test/negative1.yaml": "67db48dcb14a99e5a5d65bfb5280b76567028ef24bc2a8a5694eb5daa84c2497",
    "assets/queries/k8s/memory_limits_not_defined/test/negative2.yaml": "13643c81c5d4f48606488866d7299eccc7497c07df240ad381823573130e5251",
    "assets/queries/k8s/memory_limits_not_defined/test/positive1.yaml": "7b89844325d4cbdd26f879f4bb0042aa480e25f603ddde841f65d29f7a571d0f",
    "assets/queries/k8s/memory_limits_not_defined/test/positive2.yaml": "7ef977e964a31e21df92fb5fa2316ca025ab98d5e74cb9695d1b353e8b692913",
    "assets/queries/k8s/memory_limits_not_defined/test/positive_expected_result.json": "1388dd7ef5afa8f6ef10e58f13b1ae9b393248ba991ce6da6aef8a24233ff97e",
    "assets/queries/k8s/memory_requests_not_defined/test/negative1.yaml": "024f1f7b6395b39d3a669310faf2de2136aaea071aca23f044ed29e5b78c0342",
    "assets/queries/k8s/memory_requests_not_defined/test/negative2.yaml": "ab3c0b93b76afcc216d758cb6bb41b9bb302dc273ec52f6de5d97a0488ca2edc",
    "assets/queries/k8s/memory_requests_not_defined/test/positive1.yaml": "cf7bb23323f8fdaa78f0b51f347f6ef6bd7a7c2d740651545194ed48f70e6957",
    "assets/queries/k8s/memory_requests_not_defined/test/positive2.yaml": "e3c66ce72e4c5119acfca6ca661eadd2446cbaade09efc3d7e1e6e071300a4b9",
    "assets/queries/k8s/memory_requests_not_defined/test/positive_expected_result.json": "d952540cec7aaff6d7afd847a87d2cdbe2aa518129754e22526e1e26a3bcb920",
    "assets/queries/k8s/metadata_label_is_invalid/test/negative.yaml": "a10e8e543ac81845183eddb97504ff0589bfda01295c676ce41b65fc9c17c60e",
    "assets/queries/k8s/metadata_label_is_invalid/test/positive.yaml": "091e6011eeabd04906ec3909babbd3d3283e5462513f7a59bb7020b682639406",
    "assets/queries/k8s/metadata_label_is_invalid/test/positive_expected_result.json": "9eda08b6aa6b8fe7a169d87a43c7f05ad45d4fc8a8a35fca7ba7b87461bde35c",
    "assets/queries/k8s/missing_app_armor_config/test/negative.yaml": "a1b6aacf87e63a7e999a686d6518109d0e285ee77cf4fc614ac57cb23887bbc5",
    "assets/queries/k8s/missing_app_armor_config/test/positive.yaml": "b3ba0dead735b12a2c5110e0fde9a8dac114fda7f4679fd675043f7d2d086c0e",
    "assets/queries/k8s/missing_app_armor_config/test/positive_expected_result.json": "2f824877e8edd1785efc298daf9fa0c6b97edd18497cf72a2db4ce8d80c3d6cb",
    "assets/queries/k8s/namespace_lifecycle_admission_control_plugin_disabled/test/negative1.yaml": "e2e3cfca39d39a81ba80f06b6f21d7a03a4c716dd41aae6a62f09214c2a55f66",
    "assets/queries/k8s/namespace_lifecycle_admission_control_plugin_disabled/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/namespace_lifecycle_admission_control_plugin_disabled/test/positive1.yaml": "cc8e879ad65a69487db889c41b87decf5ff0b0ed6dd5e806792053bea4064fda",
    "assets/queries/k8s/namespace_lifecycle_admission_control_plugin_disabled/test/positive2.yaml": "7cf58c9ea03f490ba257b572365a65051cc57e9bb06fa858f355e1db751a2db0",
    "assets/queries/k8s/namespace_lifecycle_admission_control_plugin_disabled/test/positive_expected_result.json": "be2782bac8233841c366f6a6bce8acba9c0d8a6c65fa9a52089148cc995bdfa8",
    "assets/queries/k8s/net_raw_capabilities_disabled_for_psp/test/negative.yaml": "b31f987f439f81b4bc0d073d12676130b33fc48a474b8b7eae75f3306a1c53ea",
    "assets/queries/k8s/net_raw_capabilities_disabled_for_psp/test/positive.yaml": "5086ef2ef3ac637c91a2631ae28b91de9923a99a8b27d4fa016e58dbf5258787",
    "assets/queries/k8s/net_raw_capabilities_disabled_for_psp/test/positive_expected_result.json": "387ff36da50ab700bcd7c70c8353a46ef3130ff7e91063f93f2a3960e2e5d9d1",
    "assets/queries/k8s/net_raw_capabilities_not_being_dropped/test/negative.yaml": "a2845d82ebab7c6a1c2552d918e4d205446dfa4c4dbffa72c692c488639b23e1",
    "assets/queries/k8s/net_raw_capabilities_not_being_dropped/test/positive1.yaml": "d5a6f77c33e45a246a9e5021c7f32a61d8b6ce0569b0f624235c88029e229f41",
    "assets/queries/k8s/net_raw_capabilities_not_being_dropped/test/positive2.yaml": "adf4e80ccf3d01e970f34a4a89a4d69ab810162a6efe93c5f94809c2ae4e93f0",
    "assets/queries/k8s/net_raw_capabilities_not_being_dropped/test/positive_expected_result.json": "19a263355487b007b6a2157c31ce49c1e7a9d66865db192c99b0e9106bd6b302",
    "assets/queries/k8s/network_policy_is_not_targeting_any_pod/test/negative.yaml": "afd71e11a3218fe4eb4f9908439e0c98fc0404343094f3af2e490ce3b768ca48",
    "assets/queries/k8s/network_policy_is_not_targeting_any_pod/test/positive.yaml": "30b5335fefe4649bf4797f73ab26b414f3be96acefe422d026315734a8a8ac97",
    "assets/queries/k8s/network_policy_is_not_targeting_any_pod/test/positive_expected_result.json": "8d6f9bbc241b625cda2e483646f0b48190901473ac467b2f2c3aca92bbe0299d",
    "assets/queries/k8s/no_drop_capabilities_for_containers/test/negative.yaml": "22d7fb22ebd7d811dae1715f5aba5706246f3f8b19cc801bd6502efa5ded00fc",
    "assets/queries/k8s/no_drop_capabilities_for_containers/test/positive.yaml": "650cb33b1e4dd7809d19ddb9ea961da43d872085ffd267f03629e1ef1a326339",
    "assets/queries/k8s/no_drop_capabilities_for_containers/test/positive_expected_result.json": "887b4462cc851a78b7f65e684a784f4cc95715adf5c8f983010142541f5bc4ee",
    "assets/queries/k8s/node_restriction_admission_control_plugin_not_set/test/negative1.yaml": "40d4d668206c895601fe0726fa10f5af048b66a8c16dd4287fc35fe8bcfb6ead",
    "assets/queries/k8s/node_restriction_admission_control_plugin_not_set/test/negative2.yaml": "549d38f33c8c2803bf25c363d6bc27e0c89150634d7a1c2119187f1ee4f7d266",
    "assets/queries/k8s/node_restriction_admission_control_plugin_not_set/test/positive1.yaml": "75bab1424f9205083c476bba7d63886b079f103d0445fcf124b0e511cd1c7cab",
    "assets/queries/k8s/node_restriction_admission_control_plugin_not_set/test/positive_expected_result.json": "2f161158233a3e9d90c38cec056f4ca262c9b97e71f1b0d63a63410ef61f162f",
    "assets/queries/k8s/non_kube_system_pod_with_host_mount/test/negative.yaml": "dcca96563cc875bc2c6eec5657ce11a6de6ea3baba8d49f4a091dd7e234dd339",
    "assets/queries/k8s/non_kube_system_pod_with_host_mount/test/positive.yaml": "6ae724d44c3102c89eeb05a95b408cb0f79ac49f573cd87ab2caba897abc5430",
    "assets/queries/k8s/non_kube_system_pod_with_host_mount/test/positive_expected_result.json": "7b36fd37730cf1cb2647afa7dfd8480b7ed991bdbe5eaf7b12d44a75540b15a7",
    "assets/queries/k8s/not_limited_capabilities_for_pod_security_policy/test/negative.yaml": "8f214a269ba0b4b0813a26ed9f032a2e975a524f88a15d53c02e875cb0908ea0",
    "assets/queries/k8s/not_limited_capabilities_for_pod_security_policy/test/positive.yaml": "359bf1490faf30f4e57476c509770c5d7a7945415a7cc902d5a5b5f761ee016c",
    "assets/queries/k8s/not_limited_capabilities_for_pod_security_policy/test/positive_expected_result.json": "04e75c6d999c8157cb53076274a21fb3517db80614a5dfe1fc6aaf4ac5500200",
    "assets/queries/k8s/not_unique_certificate_authority/test/negative1.yaml": "01798f63f5579afb355d90302a727be711c6c8f3069bd35ffa3e4c48578a2096",
    "assets/queries/k8s/not_unique_certificate_authority/test/positive1.yaml": "f8d19bab4adce07a9352748fee33722c23a673c2437b9e4c287f4f70f79743fc",
    "assets/queries/k8s/not_unique_certificate_authority/test/positive_expected_result.json": "047c40b5d9dcf06537893c45401e9a936357293f64f2e9662ea4e7440d576bf2",
    "assets/queries/k8s/object_is_using_a_deprecated_api_version/test/negative.yaml": "ced229d90d0873597bfc5d8323da89027f306556502d62662265e1e66b62b92f",
    "assets/queries/k8s/object_is_using_a_deprecated_api_version/test/positive.yaml": "dc2eb43a82a51acdb1da79471cfc08292cd5804e5b1e8bf8157369c1912d2852",
    "assets/queries/k8s/object_is_using_a_deprecated_api_version/test/positive_expected_result.json": "3ea7515bcd57d84f342b87cf51afecc3bf059ad7f6488d0325357217cc5ef153",
    "assets/queries/k8s/peer_auto_tls_set_to_true/test/negative1.yaml": "372913abe8f262992d0b8dddd48379fb4fdc0dae60f6eb0888fb576ab44524ec",
    "assets/queries/k8s/peer_auto_tls_set_to_true/test/negative2.yaml": "b05029a213bc1dca07a231fd83e8dc19e9cc271917bf34eff3af34466fd1f058",
    "assets/queries/k8s/peer_auto_tls_set_to_true/test/positive1.yaml": "bc06260fd454f2200d6a6ea108bef4eb05cf330cb06150c251bbda4634e21e83",
    "assets/queries/k8s/peer_auto_tls_set_to_true/test/positive_expected_result.json": "f6dd8b3963f44c06075b679bc5a3d97d469e042c8bd39bb439024a01bda95aa5",
    "assets/queries/k8s/permissive_access_to_create_pods/test/negative1.yaml": "23527452c2daee05acbe9a53730a375a4237d992df0824f14ac9c7be552f23a8",
    "assets/queries/k8s/permissive_access_to_create_pods/test/negative2.yaml": "670b36635460fee306e51b47474b5dfce7bb86f6cf8187a477ed23f0ff6fee1b",
    "assets/queries/k8s/permissive_access_to_create_pods/test/positive1.yaml": "cd8fb38639bcaf06a69b8df07cf7f142309955643f4d147bc3e9aa38b6e93eca",
    "assets/queries/k8s/permissive_access_to_create_pods/test/positive2.yaml": "5c1cb9ae5cf7650d7d345278afb037196037a5c6418f1b0530cfe41292864c83",
    "assets/queries/k8s/permissive_access_to_create_pods/test/positive_expected_result.json": "d9f2d04900bdb77437a0e8ed8ffb06439556d1d409513b2805b53ff183d6cfc4",
    "assets/queries/k8s/pod_misconfigured_network_policy/test/negative1.yaml": "70d0b7e92390de7dd1c9e068bc5d8d6509a956064d773821613f53d6de482228",
    "assets/queries/k8s/pod_misconfigured_network_policy/test/negative2.yaml": "be312d333edea137d12375c1910a34d4bb7905fd15561b67a873d155d89f32bc",
    "assets/queries/k8s/pod_misconfigured_network_policy/test/negative3.yaml": "7571415c2e265a3a2c45f07d10be72720f6e337d0ac5e7178ee976e833818333",
    "assets/queries/k8s/pod_misconfigured_network_policy/test/positive1.yaml": "0597ff270ed9b517bb88c7f652d16dbe0d37e1ab79303abb233a4509c458612b",
    "assets/queries/k8s/pod_misconfigured_network_policy/test/positive2.yaml": "b32ec431144882c71b8e287bf7fc552d3d000467f7b99f5ba56802b77e93ed70",
    "assets/queries/k8s/pod_misconfigured_network_policy/test/positive_expected_result.json": "c2926708d0f7ececdfebeba3ee307db785c99e604f1a8a66a8a8eee3a1c143d3",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/negative1.yaml": "37df096263fa65757e0763e805f6f1eb67b84508533b0ea623a0ffc161fd860e",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/negative2.yaml": "ccbb14f764bb502d6e9465d2d282cd5430e0859776d64147c9a18c9c96cb5d9a",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/positive1.yaml": "c1536415d5db446fcbb6f97d46e0ec4c6cc7bb0a22fceece49963b2cc44157e2",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/positive2.yaml": "111085a313d4553079c6922170624eebf407abe17956be36325962b41ae534db",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/positive3.yaml": "2b0acb47a64aacc052dd9be49c3578bf535c51fa6619c50b4488d1bc65327097",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/positive4.yaml": "d9113154a0ab1d7024ba8c4a7d17d9f6d20f212f1e92a44bc0e58fc1d7fdd704",
    "assets/queries/k8s/pod_or_container_without_limit_range/test/positive_expected_result.json": "4684e2b13ad76cb4af6e60da09439e9b2185cef06b5436d8cce72fd1a5c1acef",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/negative1.yaml": "aabd0b2fde811275dc8e7e0423b5891fed598e24088d913a9e5b50c76bb3b761",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/negative2.yaml": "b67dc50a427c05f9afd9f83239c179fd3fbaa418cfc427d9081b3cfedeab629d",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/positive1.yaml": "ebf9e49c493b657e5c0a249484561817d6ffd881991ad1171f710248dc0dd7d9",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/positive2.yaml": "29dbb070f736a45b9bceecaf27349da45e9d4b7600cfe10a3b2de6c3986d3b68",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/positive3.yaml": "14b2de0764bec451cad4f79901e6909b93d834736dcce07ed56ec44c1a4d1d01",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/positive4.yaml": "d9113154a0ab1d7024ba8c4a7d17d9f6d20f212f1e92a44bc0e58fc1d7fdd704",
    "assets/queries/k8s/pod_or_container_without_resource_quota/test/positive_expected_result.json": "f134fec41952f901f74ac2995c1f5bab867862ef6fe2b8ab60e526773db47ddc",
    "assets/queries/k8s/pod_or_container_without_security_context/test/negative.yaml": "7a1391c6319ab4be2c8724a36066e209b62616087ea8ce317802d26df6a62bf6",
    "assets/queries/k8s/pod_or_container_without_security_context/test/positive.yaml": "5ba41808a6ce1f1e7fafd6316cf620370ba93ee9ba73e89684f1d735aae12270",
    "assets/queries/k8s/pod_or_container_without_security_context/test/positive_expected_result.json": "15f4838bda5b40d1065b933f3f0a61b536414c38f5ec8646e1540bf9f7e6644e",
    "assets/queries/k8s/pod_security_policy_admission_control_plugin_not_set/test/negative1.yaml": "066fa5953e34b06bd138b7162a787f34a00dd9180664e5ce10ede49d10e0b067",
    "assets/queries/k8s/pod_security_policy_admission_control_plugin_not_set/test/negative2.yaml": "cb2f87f3a5961978759d243af54f9323d189a2987d3413cad15d9074a06f90ba",
    "assets/queries/k8s/pod_security_policy_admission_control_plugin_not_set/test/positive1.yaml": "75bab1424f9205083c476bba7d63886b079f103d0445fcf124b0e511cd1c7cab",
    "assets/queries/k8s/pod_security_policy_admission_control_plugin_not_set/test/positive_expected_result.json": "b10557b0bc289c2057b1f39d5a1aeeb142d5af82db81c90bcf873d8ebca92941",
    "assets/queries/k8s/privilege_escalation_allowed/test/negative.yaml": "6b36657c9731fd0df2316fe7f8492ee44bf70df51cf17a1a1d7460e5813a2fd5",
    "assets/queries/k8s/privilege_escalation_allowed/test/positive1.yaml": "cd9707862a5bb348c017c25545c5432d96be6b352f9dc43f64f7a0a5c1db8c68",
    "assets/queries/k8s/privilege_escalation_allowed/test/positive2.yaml": "13b469b010b4e11596c9400e1ca70e3a7a9a91a1af7aaca2078f674820cddb4e",
    "assets/queries/k8s/privilege_escalation_allowed/test/positive_expected_result.json": "3f93dcf014c8e8f76ee0c37de83770fbb85f5b2cebbdff1d7d271565f2f970d8",
    "assets/queries/k8s/profiling_not_set_to_false/test/negative1.yaml": "6de9006661ef5787e985d4ed4f57eb841f8899ecb51905960bb74e778466951e",
    "assets/queries/k8s/profiling_not_set_to_false/test/negative2.yaml": "836c84fa9749f287fb854d302683cd1cda74344e6e5891842036d6701fcd5edb",
    "assets/queries/k8s/profiling_not_set_to_false/test/negative3.yaml": "1a13d86a928126431af1ddb8cb506dc94ff872be5a6cca291237cd3bae51d0f7",
    "assets/queries/k8s/profiling_not_set_to_false/test/negative4.yaml": "1d17fa92f20032d22cc01a46d21825d99d52f5af6f2bebc5a45b5bc06fbe7a90",
    "assets/queries/k8s/profiling_not_set_to_false/test/negative5.yaml": "cb68f27ecca209a32d68455921535e34cfc7b699ead9d0b843ef145bc377636a",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive1.yaml": "c369d74142cedec6d0829b9304e0023314d1ba51e87cd94ca3de96e8b1e1ba7f",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive2.yaml": "031c6f66558638772b41efaca9f4992175c84c7d0f4a9f5f4c8360ff0cc1b460",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive3.yaml": "3e4a70d2ba0b8bed4c29c0251d5db6810abd6a6aeb5cfcc63ac9ba6db05237db",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive4.yaml": "0703f1f6b8d80237e39e56a9a83fd3eff0e2c027b8dd3be7f3cd1979de0ce69b",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive5.yaml": "ce6cdb5a297904f4ad8892c37434b1fe84b375c5196ef4afd6a9a0e16970985c",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive6.yaml": "c08d6e8305049eac105f8770bf7750bff2cb8285a2831b0846a69eda4119dbcf",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive7.yaml": "373dd8bb8f88420af8d6b05ac710c82fe15a3771cd4df529866e9751a40c390d",
    "assets/queries/k8s/profiling_not_set_to_false/test/positive_expected_result.json": "589595a3aa093af33ff12328f975ea6d15055e756f54684ae42b13e1dabe98b3",
    "assets/queries/k8s/psp_allows_privilege_escalation/test/negative.yaml": "5e2753c4955ef76652399e1a86f6853e3b42fe250b92ea6228e69cf0e79c6c03",
    "assets/queries/k8s/psp_allows_privilege_escalation/test/positive.yaml": "15b60f9d443da5b14531e2749e3f811075acbdb8be763cf126d835d3771d909b",
    "assets/queries/k8s/psp_allows_privilege_escalation/test/positive_expected_result.json": "80cfc38c8ffe85f13da24c336903f621fdfd388315433ea7d44b6c594f6d3835",
    "assets/queries/k8s/psp_allows_sharing_host_ipc/test/negative.yaml": "2847c3e1a3d78e87429bacb49540037fb971ba8bc0d0509a60a9264d1414f6bc",
    "assets/queries/k8s/psp_allows_sharing_host_ipc/test/positive.yaml": "19a36c3758f85531abc7f5a0c04732533b61c9a4ade1c42f65df180ba31fca96",
    "assets/queries/k8s/psp_allows_sharing_host_ipc/test/positive_expected_result.json": "48240294293b0ea58f61cd4fdd0d256bc5d1ff494a34102d89ee16ebb2892cb4",
    "assets/queries/k8s/psp_allows_sharing_host_pid/test/negative.yaml": "95edd21e9cfb7dee762be665d116cef3efded8c306c09bf7549f112299c11dd6",
    "assets/queries/k8s/psp_allows_sharing_host_pid/test/positive.yaml": "27bf403b3a9955ea58279d995f983029af4b0bca345a58be562d49c69bd53b3f",
    "assets/queries/k8s/psp_allows_sharing_host_pid/test/positive_expected_result.json": "ba0bae6e44787c84455d7b2681c3651ef601e14633724af91a4e46065c462ae0",
    "assets/queries/k8s/psp_containers_share_host_network_namespace/test/negative.yaml": "56703157253659d1133b22ab93ef03d9aa64146d334491b8550b386f29af68e2",
    "assets/queries/k8s/psp_containers_share_host_network_namespace/test/positive.yaml": "3fd4beb6cf0a60613bdf5cad3f94a62fe0996a8eccec4fdb57807b0d2fbbba54",
    "assets/queries/k8s/psp_containers_share_host_network_namespace/test/positive_expected_result.json": "b6824be22bf44d12c24641d765ea2480f31d7006c565f1cb0e1f2bd6deb0a006",
    "assets/queries/k8s/psp_set_to_privileged/test/negative.yaml": "f5bda8ae33da7bddd606e5a60220a3fd1f94ee12e116ba9772f6d2b424d54e98",
    "assets/queries/k8s/psp_set_to_privileged/test/positive.yaml": "4b5c27f07f2a5b0dcf82473a1584b728b82c637b4e13831b5ba4a61ee94f33f8",
    "assets/queries/k8s/psp_set_to_privileged/test/positive_expected_result.json": "b61a9173f44d20dc5853ebae283f693175d4c3effa85735ed2b8b1bb64946634",
    "assets/queries/k8s/psp_with_added_capabilities/test/negative.yaml": "19c702376b7b8e5536d784c15f894a80e0d265d15db68f5697677ea2dcf4a98f",
    "assets/queries/k8s/psp_with_added_capabilities/test/positive.yaml": "b15cc50eed2eb6f7e0b046e170ec1082e5b2b9dc07e0766ac82d6bcf3f676fec",
    "assets/queries/k8s/psp_with_added_capabilities/test/positive_expected_result.json": "09aebfc28243e18ac4c0dc8dc5081e340dc39a82ba55c10f0ce06e6478913b5b",
    "assets/queries/k8s/psp_with_unrestricted_access_to_host_path/test/negative1.yaml": "6f73869caa5d33dd425640a88c982d2c0df19e5c344e3d1e0cb030ed3151d5a8",
    "assets/queries/k8s/psp_with_unrestricted_access_to_host_path/test/positive1.yaml": "3ed23414d22de91044793e16ae28fd664c8ff2307807d7ab524f0819265ede27",
    "assets/queries/k8s/psp_with_unrestricted_access_to_host_path/test/positive2.yaml": "ef2ebbe31c09f2c0270eec41cadb08219d0be812ee07ceaa1cfbb02a0525089b",
    "assets/queries/k8s/psp_with_unrestricted_access_to_host_path/test/positive3.yaml": "0e547e8e093777139a5be6dbcceaf275d586d38837ec6e30067fd95d85361841",
    "assets/queries/k8s/psp_with_unrestricted_access_to_host_path/test/positive_expected_result.json": "912c6513ee68565256cf1e8adb5ac53787804f9dede150b0cf93c57c07990d46",
    "assets/queries/k8s/rbac_roles_allow_privilege_escalation/test/negative.yaml": "15f081c5e41ca36d9551de4b2afa1f976f316b2ebba2f01dfebaeb57fbddd222",
    "assets/queries/k8s/rbac_roles_allow_privilege_escalation/test/positive.yaml": "ccff14d9d2d6136041e9d8b9982eb3e56978ee0cd18de0de56db6d003db1b5cc",
    "assets/queries/k8s/rbac_roles_allow_privilege_escalation/test/positive_expected_result.json": "6f01d31120cd51447f2ef271d9533be507e68fbd95f7688f8a2ffa38c380177c",
    "assets/queries/k8s/rbac_roles_with_attach_permission/test/negative.yaml": "d58363adf460ac562000cbb1b47250e790202e760573ead82b8d2f2702e01971",
    "assets/queries/k8s/rbac_roles_with_attach_permission/test/positive.yaml": "aa87284741832c67d2cc0ed968da156d70b73da14501df79685cfad557e39b69",
    "assets/queries/k8s/rbac_roles_with_attach_permission/test/positive_expected_result.json": "ce79ddfb571641ffa935f83757f2f0de5135c53723c4c4c105eb6c785c4eed54",
    "assets/queries/k8s/rbac_roles_with_exec_permission/test/negative.yaml": "9c130669a0dbafb2f78ab546bec9376f89625febbe222f5dbdca318ec096eafe",
    "assets/queries/k8s/rbac_roles_with_exec_permission/test/positive.yaml": "d382447850d6236127be4b50f6ede137d7c18d0c580e43dc9fe2235bb199b424",
    "assets/queries/k8s/rbac_roles_with_exec_permission/test/positive_expected_result.json": "36f9399a20623309cb3a67b6d9021bb0b72fc24284d1a082ce7058d76760c3dc",
    "assets/queries/k8s/rbac_roles_with_impersonate_permission/test/negative.yaml": "82bccc12cee096fb51d38ba3f2292e9139e3a054ca99e0ec7b7dd3102ef6ed31",
    "assets/queries/k8s/rbac_roles_with_impersonate_permission/test/positive.yaml": "656d319e6e2851e0ef97e03a900d1dffff661d72adf39995f30f1f59c4cedf89",
    "assets/queries/k8s/rbac_roles_with_impersonate_permission/test/positive_expected_result.json": "d7c3e228d01c4c2086c822571513db291e80dafd6e5155d3e50124c04eb00663",
    "assets/queries/k8s/rbac_roles_with_portforwarding_permissions/test/negative.yaml": "17338bc415b440efa9de1cf53c7a5d6c559cc43b17dda269521a1cdc61694b85",
    "assets/queries/k8s/rbac_roles_with_portforwarding_permissions/test/positive.yaml": "d0308d93eeba310586b4b5c7a218d05451efcaff23fab169a4767806583c33ea",
    "assets/queries/k8s/rbac_roles_with_portforwarding_permissions/test/positive_expected_result.json": "df7f7a2f490f36b70cf5d15505275a1c1f6ca99258c4cac0ff921ff05753cd16",
    "assets/queries/k8s/rbac_roles_with_read_secrets_permissions/test/negative.yaml": "20fbf05c472f9531787f6d0f7793f77f507238adbc8bffa61d54dd1e5d8dc8fa",
    "assets/queries/k8s/rbac_roles_with_read_secrets_permissions/test/positive.yaml": "f98a3e5277176f34688f64769f2ec1a104550e69e621814098957d93e361be17",
    "assets/queries/k8s/rbac_roles_with_read_secrets_permissions/test/positive_expected_result.json": "35911b428a82469fa0228a40427c6a7da2277293077636fb12f08c7bf84735c1",
    "assets/queries/k8s/rbac_wildcard_in_rule/test/negative.yaml": "eaea29fa8d4c9e0904c808dc128d453c15b961386fb8c9f74a217d8f1f73b4f2",
    "assets/queries/k8s/rbac_wildcard_in_rule/test/positive.yaml": "5879d31a51b08a120161096ee4882eec0af859b6134e5584c6523b1467e35e88",
    "assets/queries/k8s/rbac_wildcard_in_rule/test/positive_expected_result.json": "60475d021a8ab0e5be173c9e7b9fb73cd986e8bd281195812e19108e3105f2e6",
    "assets/queries/k8s/readiness_probe_is_not_configured/test/negative.yaml": "a10e8e543ac81845183eddb97504ff0589bfda01295c676ce41b65fc9c17c60e",
    "assets/queries/k8s/readiness_probe_is_not_configured/test/positive.yaml": "1057a0d64ee1f96a0ca64be5f137af7372f2630024ca35e2a7670939cbd873cf",
    "assets/queries/k8s/readiness_probe_is_not_configured/test/positive_expected_result.json": "bc9e404458f2c7de3fad4f654c556676c27aeac5121d3db8e7b0e1ddab1dc50c",
    "assets/queries/k8s/request_timeout_not_properly_set/test/negative1.yaml": "fafea07681b462ec60e6da60356b3018ef45c0204bd0abd3ba333fb7049e6660",
    "assets/queries/k8s/request_timeout_not_properly_set/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive1.yaml": "bdd40cf9ff414b3de98328073f94d97492688037c8a559a8dacff8bb9e0f7b12",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive2.yaml": "bbd359a0a1c0f06fc8a8bfb50abd43b1eab0c87eedf8458bd6364ade1071b51b",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive3.yaml": "399f8cf1b06bd4d936ad95c3966bb6117fbbed74a1ebbb1c95fd4491b50a7acf",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive4.yaml": "5aa1bbcdc55233f31c98aa5a55998fde070135d3ad8f9362d5d9e8827c931fdd",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive5.yaml": "4b40bebc65d37575969a6d077a6cf8e7d318b16ca275598f12fb9e0db18f99d0",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive6.yaml": "528687efa152ee06c924c974540ac9ecf6a4d496956b8e6bf26fe735069e0753",
    "assets/queries/k8s/request_timeout_not_properly_set/test/positive_expected_result.json": "5e1022c94870aa972b7478d0c593e08324cee070421172c82ee79c5d8393e2bb",
    "assets/queries/k8s/role_binding_to_default_service_account/test/negative.yaml": "fa3be8897ee8e0457104b4882bcde77664c018255bb7d68f1d02e753acc262c5",
    "assets/queries/k8s/role_binding_to_default_service_account/test/positive.yaml": "2d470a827d6e3c08e54a421718170eb788af957cf76113d27527efdb18e184f5",
    "assets/queries/k8s/role_binding_to_default_service_account/test/positive_expected_result.json": "c0429706ae709e3b804ccc7daf73bc8f02f804e92093b5ff59618e77e526187c",
    "assets/queries/k8s/root_ca_file_not_defined/test/negative1.yaml": "a2cbb4d5c052bce2c3d8b4d09c33dc7f051cee9e11f2696e6d1ea3fa64e13c88",
    "assets/queries/k8s/root_ca_file_not_defined/test/negative2.yaml": "26d2d596b70bab2e59be97316ae0634ced84331ab198426f174e2b8950ff640e",
    "assets/queries/k8s/root_ca_file_not_defined/test/positive1.yaml": "76ca41e2f5633deddb28ee7498ace083ed895c05165aabb2e00f2f3da357f7ee",
    "assets/queries/k8s/root_ca_file_not_defined/test/positive_expected_result.json": "616c4b3272c1ad22989be041244e620d1ded16f120cae19246c77ea577a33f93",
    "assets/queries/k8s/root_container_not_mounted_as_read_only/test/negative.yaml": "b4fabee22b43c87f37a1132794afd2badd39af397b4701d210ba6fee048fd072",
    "assets/queries/k8s/root_container_not_mounted_as_read_only/test/positive.yaml": "35f7c6f5a1553d3f738be0a9b7e40ece44bcd79f0f017a338ba76a706b52f7f4",
    "assets/queries/k8s/root_container_not_mounted_as_read_only/test/positive_expected_result.json": "e10fa4826e28fc4e867b9199392223c972d31c906e058176ef8dd8868c21fcfa",
    "assets/queries/k8s/root_containers_admitted/test/negative.yaml": "e699e8eb9c13f21664b33c4331358f643cc8dd99e5476fee32aba8a0361e3929",
    "assets/queries/k8s/root_containers_admitted/test/positive.yaml": "3bc62b5f395e92678321edd9329385aa44cd643870a6ab8c5c3b3a86a6b6a811",
    "assets/queries/k8s/root_containers_admitted/test/positive_expected_result.json": "ecf29c39dbd17e83ba6a1e68fce846ea20489b04c6008af85c2569286ae8e787",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/negative1.yaml": "c07255126dd58ef5c8de7306ccc1b1c0bd4b8f20f7550f933e625a43447b3d08",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/negative2.yaml": "52dea5888ca8e4c8ba769eb0903c5b1bc993589bc70dc17388b8f12819e5b85e",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/negative3.yaml": "5d9975e5278123c2a2cbeaf84e0bc9f7812a9fadeca770e95255eeb6c27061c4",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/negative4.yaml": "6ee5c2411c6f91fd1d15d072f596cb180466f19ec391d3570306bf5515e37e38",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/negative5.json": "bd1fe03e046b4fb84312a352efcc52557cd5cf7e8300ec9374bd057ce44d8124",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/negative6.json": "081e0138b31f304031fec5cfef35cbbb128a6142bd08d6dc336d4c50fdf2b8a8",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/positive1.yaml": "63045bbfe12598adf6502314a58d4e0184a1d8e15005210121b1c79d134d3a8c",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/positive2.yaml": "1676d51f1d31631b11df6eb8ddf43dad63e8ba7d805dd39c039e915de8258c4a",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/positive3.json": "277256d8682398ab1ba4fa1eb5e3eb24c01739ea60103101f6ab8a57513088f6",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/positive4.yaml": "74379d00189a322db86741c21c50afc84ac8e3b4a8b23561067d437f06892e72",
    "assets/queries/k8s/rotate_kubelet_server_certificate_not_active/test/positive_expected_result.json": "f2d4d3c988cb2dae9801b8ae766f12645a14c7a42312fd5a3ba6f1e903c4be48",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/negative1.yaml": "0d5ebb698b903bac77a5edeb71847970bd76d7f38f4061a4a132f5384a583d22",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/negative2.yaml": "e4383e01275b682a3f886e6c9436946514ec39155247abed1d5da75be2a50ad5",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/negative3.yaml": "0a13f01f0986106ab038f6340fde752ad2e25ef43c42a475c826bd30fbd3e42b",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/positive1.yaml": "5f2c32958c03a0e82488f314d40ea1a7067dfe439f6cf7ce89c363fff91a0f2d",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/positive2.yaml": "8d44ba7d5cec32ef915b148b094bbfe666b33263b61a925225ee4809949cf1cb",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/positive3.yaml": "8a10f79fcf6bb5bc5d45412c903da014f7be107060e5e4ad91cb5549d21d922f",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/positive4.yaml": "cbb13a20ffb12211f0cce3620519b79a8bc855379f4803d8a0915d281130a8fe",
    "assets/queries/k8s/seccomp_profile_is_not_configured/test/positive_expected_result.json": "32f39df3f11fc9f1033c475e7ed6b2b097b7b2f60d2c79ab61819acbc08021b7",
    "assets/queries/k8s/secrets_as_environment_variables/test/negative.yaml": "29f06e879e2f10cb29666aa5f260a663db1a406cc2a3348132af5669d2ae13d3",
    "assets/queries/k8s/secrets_as_environment_variables/test/positive.yaml": "5d778bb884f160649ed35d9f851fda78c318b8e6067ed7a0b72b9e8fd36536f7",
    "assets/queries/k8s/secrets_as_environment_variables/test/positive_expected_result.json": "14100bccead2beb7579e00ad9f2bd38c3e5218e6fa47fee7f5eb8a2892e75700",
    "assets/queries/k8s/secure_port_set_to_zero/test/negative1.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/secure_port_set_to_zero/test/negative2.yaml": "7c7b662813e72cf8098df7d63f4a3aa24a4ea077294dc78c456429313056302b",
    "assets/queries/k8s/secure_port_set_to_zero/test/positive1.yaml": "822d94d71601c6e01c63c3a48c5238922cf3923fc2f048f36485a30742dee0fd",
    "assets/queries/k8s/secure_port_set_to_zero/test/positive_expected_result.json": "7811950b7dcced5b3997401e90815acc19d5af973ae44dab2fd8ececc1330168",
    "assets/queries/k8s/security_context_deny_admission_control_plugin_not_set/test/negative1.yaml": "13b8cd9a0f23b70b340657132003147687434c07bb4892b25fc3f782b40e19d2",
    "assets/queries/k8s/security_context_deny_admission_control_plugin_not_set/test/negative2.yaml": "f6877996cfb992d4eb17c64e9736a771646562dbc7c70c34ea8279891495f802",
    "assets/queries/k8s/security_context_deny_admission_control_plugin_not_set/test/negative3.yaml": "cb2f87f3a5961978759d243af54f9323d189a2987d3413cad15d9074a06f90ba",
    "assets/queries/k8s/security_context_deny_admission_control_plugin_not_set/test/positive1.yaml": "75bab1424f9205083c476bba7d63886b079f103d0445fcf124b0e511cd1c7cab",
    "assets/queries/k8s/security_context_deny_admission_control_plugin_not_set/test/positive_expected_result.json": "c2a78eb2f914966ac25ac55d140dd73bfe84f07a35d7f7ac792b3c8161eb3927",
    "assets/queries/k8s/service_account_admission_control_plugin_disabled/test/negative1.yaml": "047e7950d4f97112f793865a24319fa379c95c75ba28213edfdd7c8432b9de06",
    "assets/queries/k8s/service_account_admission_control_plugin_disabled/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/service_account_admission_control_plugin_disabled/test/positive1.yaml": "62c10fc7139483499a61be4926a4270608f132a1cd2c5b8c1736ff41c47df802",
    "assets/queries/k8s/service_account_admission_control_plugin_disabled/test/positive2.yaml": "61f75f5dc40c3663cc546e3b9990ea18983e8bf29de7ee74386b4a32faf5ce5b",
    "assets/queries/k8s/service_account_admission_control_plugin_disabled/test/positive_expected_result.json": "a02b5fdca65e7dfd00bdfdcbe600400bbed03453a07e39916f64bdc2757da2e1",
    "assets/queries/k8s/service_account_allows_access_secrets/test/negative.yaml": "fd04548482e062586620af6bc8b28013b59d9da0f35d73b3c3ee03890a588906",
    "assets/queries/k8s/service_account_allows_access_secrets/test/positive.yaml": "028c964050bbdfa1e69e88e1712ee83a76d618ce7c8cd8c8d79b0788cecfc00c",
    "assets/queries/k8s/service_account_allows_access_secrets/test/positive_expected_result.json": "20dab325e1b8018bb1b0670993f20d9f2b4f35d56a1357ac406bfcdd2011029b",
    "assets/queries/k8s/service_account_key_file_not_properly_set/test/negative1.yaml": "de180b89f4380aaf456efb058cf154ff6ea7b70f09a39c60dee2dae575b6fc9b",
    "assets/queries/k8s/service_account_key_file_not_properly_set/test/positive1.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/service_account_key_file_not_properly_set/test/positive_expected_result.json": "d1c50559e1e8449c26dc603f2eb48a1cda699888c1e1c2558cdd5435c4f0d548",
    "assets/queries/k8s/service_account_lookup_set_to_false/test/negative1.yaml": "29327013596bea6a4d800e7bfd7bb981d113eb9327f3d931eb99d3d381389747",
    "assets/queries/k8s/service_account_lookup_set_to_false/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/service_account_lookup_set_to_false/test/positive1.yaml": "fc15b735c7cbb0c3c2ffe7f9d15b87a71bebf211565fa394a4057f653dedec1d",
    "assets/queries/k8s/service_account_lookup_set_to_false/test/positive_expected_result.json": "1816870de9bc5abe5cccb8aa868d3f08c9b06c3825145049a5f0130801488d9f",
    "assets/queries/k8s/service_account_name_undefined_or_empty/test/negative.yaml": "16473a3fcf42a3c6772a74f94183fefbcd3cfb021b89382c923e48340ba61036",
    "assets/queries/k8s/service_account_name_undefined_or_empty/test/positive.yaml": "9a4dbde30bcfe1460292ed21ac7c0d54002acd43274d52c83df761303f4e5fd2",
    "assets/queries/k8s/service_account_name_undefined_or_empty/test/positive_expected_result.json": "37f34528720c367116d909bc5ce6044d4ae502f69fdf9dbf064b53343c634c75",
    "assets/queries/k8s/service_account_private_key_file_not_defined/test/negative1.yaml": "534fb815c85da7d3e2d1be5bf0f30c68396c5147813994fdd3ba36e318c0b1b8",
    "assets/queries/k8s/service_account_private_key_file_not_defined/test/negative2.yaml": "6a6cff13df2661abc8f2c6c3cb35aec7bdee1800c0dda8407669f2e6816f691c",
    "assets/queries/k8s/service_account_private_key_file_not_defined/test/positive1.yaml": "76ca41e2f5633deddb28ee7498ace083ed895c05165aabb2e00f2f3da357f7ee",
    "assets/queries/k8s/service_account_private_key_file_not_defined/test/positive_expected_result.json": "01ddf50511f953d115cdf87ffc9c792f70b2c2390a95ef81851a8285db638e32",
    "assets/queries/k8s/service_account_token_automount_not_disabled/test/negative1.yaml": "f8b61af6d66d58273c46245e5831f3e6a7cb4de54a5ecaabae9181df3083cac5",
    "assets/queries/k8s/service_account_token_automount_not_disabled/test/negative2.yaml": "92d988e176d3b2337093fe1bd65e4404a9dd67cf62ac14bb36c0037c55a3a5b6",
    "assets/queries/k8s/service_account_token_automount_not_disabled/test/positive1.yaml": "334ebbe282cf6a82683b9714fdc57c59e49953020d3157dd6eda79335a9c41cd",
    "assets/queries/k8s/service_account_token_automount_not_disabled/test/positive2.yaml": "cd14dd0733c18334c26d9930a5bc350bef8f6f2804bafd79d230db2f52142d1e",
    "assets/queries/k8s/service_account_token_automount_not_disabled/test/positive_expected_result.json": "983cc21c30620f871b3b2dd73096322b811beb238976722518e8adf166581013",
    "assets/queries/k8s/service_does_not_target_pod/test/negative1.yaml": "cae1ebf20293341556e016851ac0bb019ad3cca42d45476065e9498edc25b5fa",
    "assets/queries/k8s/service_does_not_target_pod/test/negative2.yaml": "66f9c0d96dbd5c02aa2252ac249a29bbaa3df93918ef8c5f8052a2d315480fa5",
    "assets/queries/k8s/service_does_not_target_pod/test/negative3.yaml": "f79746b182d8d60f103fb559551877c2a19d4d97cb185b2cd8dc4f4195d615e7",
    "assets/queries/k8s/service_does_not_target_pod/test/negative4.yaml": "f1c5297051ea5700598ff676606deeb1d60c96366a365f448a017a8ae8e5ae1f",
    "assets/queries/k8s/service_does_not_target_pod/test/negative5.yaml": "35ee2a112143bbd17bb1c8071077cfe095479119031a90bc9a424262d941c1fb",
    "assets/queries/k8s/service_does_not_target_pod/test/negative6.yaml": "d6e22e478c510aaf475a91004d573e3005f373efb185afac34babdc98d990eb1",
    "assets/queries/k8s/service_does_not_target_pod/test/positive1.yaml": "a3016c93eac29a712602c6fd2140232c79b647d4836eee51ad5174b41680044e",
    "assets/queries/k8s/service_does_not_target_pod/test/positive2.yaml": "ca793014be7662c4431fa8a1ba36b1c3b50659b3b71a3c21d2c95ff8bd0b31d1",
    "assets/queries/k8s/service_does_not_target_pod/test/positive_expected_result.json": "40e82291d0da893860f0093bf15e2041cfa406b022c19caadaef671d3a0c9d81",
    "assets/queries/k8s/service_type_is_nodeport/test/negative.yaml": "c1970983a403bb11b12bf454c7c350bf4d64f7a92a3b34cafa32bde16b7b339a",
    "assets/queries/k8s/service_type_is_nodeport/test/positive.yaml": "da90eeea3f646717bf79281edef46fcc817c2eaa99a8643e01ad4d7c9e8ad346",
    "assets/queries/k8s/service_type_is_nodeport/test/positive_expected_result.json": "67e6bd354b7fd7b7cd27abe9217ccd31919cefc22558cc8df5b5a02cd0437ce0",
    "assets/queries/k8s/service_with_external_load_balancer/test/negative.yaml": "44b972b4c44e09d692e6af55231738e431eb85dc6bfe8b721183e88573969310",
    "assets/queries/k8s/service_with_external_load_balancer/test/positive.yaml": "74c2494c17e1ca0ed194c1e173704bd04227fb6709ae46358fee9e69a021f037",
    "assets/queries/k8s/service_with_external_load_balancer/test/positive_expected_result.json": "2b1bf08c2925cb112f097d591bc1365b6e07c652c23b44074b5e1643ab9572e8",
    "assets/queries/k8s/shared_host_ipc_namespace/test/negative.yaml": "06e2b3cc7ed45ec30b0d92bff18c5b67dfea6acfbd4660868ab5717eebcf5e04",
    "assets/queries/k8s/shared_host_ipc_namespace/test/negative2.yaml": "81f44bd71b37562b7124d2501071f8c9a0ef9638ff4ec9f9d1244ebc90f0fcc8",
    "assets/queries/k8s/shared_host_ipc_namespace/test/positive.yaml": "2add38de187229fc0363f0031524e4b96c4ce5b3b721cafb56d6c1667c6e6593",
    "assets/queries/k8s/shared_host_ipc_namespace/test/positive2.yaml": "242e25e5b30d0cdeb5bfd79c3b2cba4c67f299bd6f07567a3b4e9bae166d02a5",
    "assets/queries/k8s/shared_host_ipc_namespace/test/positive_expected_result.json": "cf0ffcd70c426cb42736b2a726dc0629ab0434d52d2aaba59f8d65d1bc7139e1",
    "assets/queries/k8s/shared_host_network_namespace/test/negative.yaml": "31ab5b9a64917312fe902f6f709934547d8a4ead431c33f2af086a938be5e1d9",
    "assets/queries/k8s/shared_host_network_namespace/test/negative2.yaml": "afb7f2de3dc5a3e6aec3cb207a09e301b91ae0f9ffb12de46243f2320279b8ad",
    "assets/queries/k8s/shared_host_network_namespace/test/positive.yaml": "28c5d32e53c6d2134732d16382934a03011bbfa1a48641025641548856faa044",
    "assets/queries/k8s/shared_host_network_namespace/test/positive2.yaml": "65a1b763b8519e414397a5a07a38d829a3fbd3827080857e1cbb77d881eee6a5",
    "assets/queries/k8s/shared_host_network_namespace/test/positive_expected_result.json": "719188132a1807c77b276d03d01bd4f2f46a8d332b489664de4151f6eabb798d",
    "assets/queries/k8s/shared_host_pid_namespace/test/negative.yaml": "30c06ea7062116fa19b154b3fce66ca32f481bb11a9ddc3a177d42b0674eaeb2",
    "assets/queries/k8s/shared_host_pid_namespace/test/negative2.yaml": "8ce9d90df99f7481227f6ae3e30efff93393b7cd1f607140a5ad7771eb491d11",
    "assets/queries/k8s/shared_host_pid_namespace/test/positive.yaml": "d94a2fa0fde3c59c61e5ce152b1b092c44fad6ce9d099c31b888d0c9ea31a06c",
    "assets/queries/k8s/shared_host_pid_namespace/test/positive2.yaml": "244f47acc8c99f68006a116b2c8f370ed5f62baba3c4793f3e90298e0b5cb0c4",
    "assets/queries/k8s/shared_host_pid_namespace/test/positive_expected_result.json": "bbfbc49c2ed61b569dfdb36d51e58deb9d4e359ad41074218028453821ce588a",
    "assets/queries/k8s/shared_service_account/test/negative.yaml": "a6d02f6b87be2f31c8a36710554a962a2ce9d2c84776a11a61f6f9ddbb1e9a1c",
    "assets/queries/k8s/shared_service_account/test/positive.yaml": "19865f7c3c898155963c9b082ce4c99f922c1af9b6977a932f74ed563b818970",
    "assets/queries/k8s/shared_service_account/test/positive_expected_result.json": "cc128209772103a85cc99b84a98cfa333542e20b87ed121da7f3c80f9f211106",
    "assets/queries/k8s/statefulset_has_no_pod_anti_affinity/test/negative.yaml": "7c5d09db19a66b2a0798730d9ec75643970b2a387096be28012b3b04806a51a1",
    "assets/queries/k8s/statefulset_has_no_pod_anti_affinity/test/positive.yaml": "5606b063dcc91206cf70f5c21d680e301936b6dd40be8aa90646ac745197b44a",
    "assets/queries/k8s/statefulset_has_no_pod_anti_affinity/test/positive_expected_result.json": "d49b249992068193d7955bca5594ee9bfd92eee141f6337c71d09fba2e790ca4",
    "assets/queries/k8s/statefulset_requests_storage/test/negative.yaml": "3442f65bc8b389ae62f6fef8e3bd3996578d799276bde5f212c6429b649adf4d",
    "assets/queries/k8s/statefulset_requests_storage/test/positive.yaml": "3fa066d5217ef18f44ba4481c095c2d8952cb7fdec352da3777a232cf81b53d1",
    "assets/queries/k8s/statefulset_requests_storage/test/positive_expected_result.json": "6555fefb840b6c7fa4701f1c5e6ec772770d23688113a3fbf51e9618427db830",
    "assets/queries/k8s/statefulset_without_pod_disruption_budget/test/negative.yaml": "26aae2b9fad573c4d087165819f6990ded1b5a62676c428636d7269bbe7eabd0",
    "assets/queries/k8s/statefulset_without_pod_disruption_budget/test/positive.yaml": "ae0aac20b246e99033f5c14684dcad31233b94d091f19080f52b803280a1ab6b",
    "assets/queries/k8s/statefulset_without_pod_disruption_budget/test/positive_expected_result.json": "4d376569446fb43748227fa0ffb3043f517e52c5c80d33c2b8c5d5a17e8a66b3",
    "assets/queries/k8s/statefulset_without_service_name/test/negative.yaml": "172e411ff9bd95529f412dc6498fbda9ce150863f2d0bb9e49681523edec811e",
    "assets/queries/k8s/statefulset_without_service_name/test/positive.yaml": "71a27e9f34cc900ac04710f3b0fb32f6adddd67a9c347645553cfbcb41257106",
    "assets/queries/k8s/statefulset_without_service_name/test/positive_expected_result.json": "398e496b3ba745234388f7c1b0fc3b7b67216dd48ab0b97a35a17237f28333e4",
    "assets/queries/k8s/terminated_pod_garbage_collector_threshold_not_properly_set/test/negative1.yaml": "320bc2c3ea64d064f00d54ea1347a622cc5652084c914d37fec020f32ce675e3",
    "assets/queries/k8s/terminated_pod_garbage_collector_threshold_not_properly_set/test/negative2.yaml": "41955b77f0b80944a8ed4d84fc7f27710f70e2867b2bbe3bc6b4dd8115366006",
    "assets/queries/k8s/terminated_pod_garbage_collector_threshold_not_properly_set/test/positive1.yaml": "33e3c815abd92421b1b3bec99571f253b53bddef7e8815d6e131fdcba70fd0cd",
    "assets/queries/k8s/terminated_pod_garbage_collector_threshold_not_properly_set/test/positive2.yaml": "39021f0fbc72af2a1f319de2e1383abff4458268016cf0625f38ec950080acee",
    "assets/queries/k8s/terminated_pod_garbage_collector_threshold_not_properly_set/test/positive_expected_result.json": "8d6908f6ded0b0659775ea2b758961ea67f0fdda87ca0fd9f8bfb7dc0ff949db",
    "assets/queries/k8s/tiller_deployment_is_accessible_from_within_the_cluster/test/negative.yaml": "55a510f509e407a492b8984b04e5851fc18c8fa0fd1a4d6e69f48b3277573ff5",
    "assets/queries/k8s/tiller_deployment_is_accessible_from_within_the_cluster/test/positive.yaml": "4ce339e0193f10f60f4e27c4e6fdea2234ebed00c03170635e3d5db2caa0c548",
    "assets/queries/k8s/tiller_deployment_is_accessible_from_within_the_cluster/test/positive_expected_result.json": "475f3253eada3480364a568c34b242fb0ad193937ff53b2aae66d3567f7ee118",
    "assets/queries/k8s/tiller_is_deployed/test/negative.yaml": "093ec78bde591137a54d5354a395395cf180765e62ab7257dbba2ad106b9f514",
    "assets/queries/k8s/tiller_is_deployed/test/positive.yaml": "9978d3a57eb808697baf990dc079a0f523377b2999460df3a4112237fab22ab3",
    "assets/queries/k8s/tiller_is_deployed/test/positive_expected_result.json": "bbbc3b90b6254be257c89014ba9c410175a6df470254caed93fc1006e46e77cd",
    "assets/queries/k8s/tiller_service_is_not_deleted/test/negative.yaml": "8b836a08d2001717a241788ff12233d70defb25ca35ac79f712470bb861b32fd",
    "assets/queries/k8s/tiller_service_is_not_deleted/test/positive.yaml": "84c26c88a03800e5b0a0f11fae5c6c7f72f7fff6f728ef0391dd1dfe5eacbd67",
    "assets/queries/k8s/tiller_service_is_not_deleted/test/positive_expected_result.json": "6f687ff9fc82a675921cbaefa2d38ebf2e3367270c0287880dcd2ebc96368bea",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/negative1.yaml": "70dcdf0afb366c60583c6ed98357e35202dcc3f06920f5c161ce37a5ba81cd49",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/negative2.yaml": "81bd260a23d7be75abee9d5f0284284b973c86e3d6834404d17892293b27aa9f",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/negative3.yaml": "4ab5f540b14ed688115f153296a261de02f24ea791b72e33ba17328b354cac5e",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/negative4.json": "e1f75c8b6115c623b69be9b16f83a2a42ccab1f1acf354da2be734e9fc8eb72f",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/positive1.yaml": "5e7c6b05abfea9228fa4842fa7f2a85d0856ca8d2a410293cefc82b33755d7f2",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/positive2.yaml": "d95f5fbaebd6d07546455ec2e2b84bfd508e68a6dcb8017c89fb2cf5c1c54403",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/positive3.json": "08f6f46e80cc3e0a7e91a3db2ddcbf2233efdf6a47520b704231cddade5c00b6",
    "assets/queries/k8s/tls_connection_certificate_not_setup/test/positive_expected_result.json": "e83f8e1db84c7c6dbe031f0bb1b3b720d6547ac1110cf318a752de36cd005c35",
    "assets/queries/k8s/token_auth_file_is_set/test/negative1.yaml": "32b06d2350713651a90e2ff2e3dc0bb51238020404872709a3ee5f22d859ed1b",
    "assets/queries/k8s/token_auth_file_is_set/test/negative2.yaml": "d5c7f26b3ad0c6bcf556174129074680bed4584ae592603d902c76c7c48e0d3e",
    "assets/queries/k8s/token_auth_file_is_set/test/positive1.yaml": "8540325e730756332f01e2571ef9992811b4743e14b419e906683838c163d4ef",
    "assets/queries/k8s/token_auth_file_is_set/test/positive2.yaml": "f1ce9220c8245a069e7239d9d0f3d4f1ed7286614865d0b745ee3db06290b50c",
    "assets/queries/k8s/token_auth_file_is_set/test/positive_expected_result.json": "90dd52ac3a5f05f2230100be39b214941df4ccf3ccd9e37c18a4f7ca10dca769",
    "assets/queries/k8s/use_service_account_credentials_not_set_to_true/test/negative1.yaml": "07d5dcf2e03c702c5c53dfbfd762274c569f439def26d8711323206124024d80",
    "assets/queries/k8s/use_service_account_credentials_not_set_to_true/test/negative2.yaml": "9796b1f206709acffb9ca0cbdf2c026a3b1f4203dfff5ab472d7c5327d6e7ccb",
    "assets/queries/k8s/use_service_account_credentials_not_set_to_true/test/positive1.yaml": "5b883cca3d2c881f10b9ff4182e22720e7c228fbff00377046d18ea59af7c2d1",
    "assets/queries/k8s/use_service_account_credentials_not_set_to_true/test/positive2.yaml": "76ca41e2f5633deddb28ee7498ace083ed895c05165aabb2e00f2f3da357f7ee",
    "assets/queries/k8s/use_service_account_credentials_not_set_to_true/test/positive_expected_result.json": "2168a0b9bab3367c34077bd341d6f7856e518cd56a3f6f610527a7f689a18beb",
    "assets/queries/k8s/using_kubernetes_native_secret_management/test/negative1.yaml": "7e12aed16737f9181b73244440d7555875cbdc0fe50dd72c2f129006e650b646",
    "assets/queries/k8s/using_kubernetes_native_secret_management/test/negative2.yaml": "b7cf8ca811702b09527eac62b74d47a99e6dfd0136c65498283f6555abc78cd3",
    "assets/queries/k8s/using_kubernetes_native_secret_management/test/positive1.yaml": "c7805ca2a75a6279eb6691855bc3dcc41fde07c621b685a15d1b67fbc5986fb9",
    "assets/queries/k8s/using_kubernetes_native_secret_management/test/positive_expected_result.json": "f9f98bd5dc8c229f0bf7912b679f46a6d6bed89034f82a144f419dcd569e82c8",
    "assets/queries/k8s/using_unrecommended_namespace/test/negative1.yaml": "f2671c613989885c8fa4b0fa9f8fc204b0dd75652f1547ba558f3b4981823357",
    "assets/queries/k8s/using_unrecommended_namespace/test/positive1.yaml": "4d6f2434ada54707d9ad8c2e9df2c345e0e286212c975d989ea39cf11e7eb5b1",
    "assets/queries/k8s/using_unrecommended_namespace/test/positive2.yaml": "fdd032371de90ebc5899b3a71f830c0292facf74b262149342eab1ff7f4fba9b",
    "assets/queries/k8s/using_unrecommended_namespace/test/positive3.yaml": "5a534bab0f62925535a759d11b811f7c315052707089c8b81048b7887970e289",
    "assets/queries/k8s/using_unrecommended_namespace/test/positive4.yaml": "787ee613415ce5bd4cb11b038135cfe295867de8722c52e96ba692b2160c8162",
    "assets/queries/k8s/using_unrecommended_namespace/test/positive5.yaml": "8cefe79c4b4b81ac387eec50fc5cc9b20f228bf1671f83e558c2043a60368923",
    "assets/queries/k8s/using_unrecommended_namespace/test/positive_expected_result.json": "d392f16996071568b31f91df419fdbc622ba5218ba3eb0fe98fa465741430516",
    "assets/queries/k8s/volume_mount_with_os_directory_write_permissions/test/negative1.yaml": "426cd74a8ea5bb99ef1f0956c230bde7b3a170e5efaab2ff281731b15a1f1ae4",
    "assets/queries/k8s/volume_mount_with_os_directory_write_permissions/test/negative2.yaml": "8d8405e0853db3794c44c0913a74f994c9f829165d29718e5da9a44c93d35fb9",
    "assets/queries/k8s/volume_mount_with_os_directory_write_permissions/test/negative3.yaml": "cf57884333e1504627c82db8c345268d09955ee24bb94079ad6bc9a6de4b4a45",
    "assets/queries/k8s/volume_mount_with_os_directory_write_permissions/test/positive1.yaml": "63bd13f57bc7a0666a9d7df8c578660406477bec45717d180d3950436114422a",
    "assets/queries/k8s/volume_mount_with_os_directory_write_permissions/test/positive2.yaml": "0e4921ff32d524dba75d0a3541168e8e58b4e028b4f84b8dcfd06171a5f46338",
    "assets/queries/k8s/volume_mount_with_os_directory_write_permissions/test/positive_expected_result.json": "f03f7618c70dd29b807e3c7c5006b7f04ab8f34c6fa8fa6def228650257b1b70",
    "assets/queries/k8s/weak_tls_cipher_suites/test/negative1.yaml": "68c5e7c0b6a4e775a474c4db3e02b13f89540c30a90178f434333ca624fba1a2",
    "assets/queries/k8s/weak_tls_cipher_suites/test/negative2.yaml": "537501d7e0229a362994364ec201c3f7a28effccd4b7d39afe7b0e066fc7a4d7",
    "assets/queries/k8s/weak_tls_cipher_suites/test/negative3.yaml": "952f761377f924c63aa2d8e5f64f527e4f37faf41bc1e5f8ed496decbe346dbe",
    "assets/queries/k8s/weak_tls_cipher_suites/test/negative4.json": "029c755077d5530d44d55d80112159183de95fb73a683388584f0c806fa1e5c8",
    "assets/queries/k8s/weak_tls_cipher_suites/test/positive1.yaml": "7becbc26e915444e14079a57d5e93e2c4fee86a3544bdf2b026956e4028aeec6",
    "assets/queries/k8s/weak_tls_cipher_suites/test/positive2.yaml": "83397278fb92140c75cdc395a618d8b3a6b310be064148a602ce706211c5ceb3",
    "assets/queries/k8s/weak_tls_cipher_suites/test/positive3.yaml": "b68b8d152eca77fb6b2c1e1f112691866733a2f88ff3639715c0a28954b15473",
    "assets/queries/k8s/weak_tls_cipher_suites/test/positive4.json": "eb1210fef4441e7f05028c9811ad59c43c93aaa0b426deb51208496379a7b150",
    "assets/queries/k8s/weak_tls_cipher_suites/test/positive_expected_result.json": "5848b84b072d6040939c634c1da434ecb84d35813025ad1afc16af89d644444c",
    "assets/queries/k8s/workload_host_port_not_specified/test/negative.yaml": "70d7d5b36b1122f77b8478bc03742ef9ce9873171252f0c1c8227308a09bb6e7",
    "assets/queries/k8s/workload_host_port_not_specified/test/positive.yaml": "714f75a4a70eece54bbf1e8c7ec2b53bd983bbbea6f93d5e077ccc8e1cb7f456",
    "assets/queries/k8s/workload_host_port_not_specified/test/positive_expected_result.json": "c4a5bab372bfca19ca29cb9892724021238326c51a03e3e7b8100cc566b96a4c",
    "assets/queries/k8s/workload_mounting_with_sensitive_os_directory/test/negative.yaml": "cf21f80f0ec7fc57ca7278d3ce5965c9aa19089692b07737fdaaa181d70d984f",
    "assets/queries/k8s/workload_mounting_with_sensitive_os_directory/test/positive.yaml": "d7eefe23448a3f827c10ce8ab7264a057740a28f392a1de17102a6e24ff3ea5f",
    "assets/queries/k8s/workload_mounting_with_sensitive_os_directory/test/positive_expected_result.json": "71057ecbb11fef559b46f5ae874ca3c7d21661b3ca9dbef66db1790ce55ae791",
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


BENCHPROCTOR = "benchproctor"
BENCHPROCTOR_COMMIT = "ad70ff85c2325626ccbda2a6565d354732d032ff"
BENCHPROCTOR_URL = (
    "https://raw.githubusercontent.com/TheAuditorTool/BenchProctor/{commit}/{path}"
)
# TheAuditorTool/BenchProctor (Apache-2.0): the 2026.07.22 quicktest bundles for
# TypeScript and JavaScript (its releases halted, so the pin cannot move). Each
# zip holds two frameworks' generated test cases, their labels
# (`expectedresults-2026.07.22.csv`) and the bundle's scorer (`score_sarif.py`);
# graded by tests/integration/test_benchproctor.py (Phase 6, F7). The zips are
# extracted into the cache once they verify.
BENCHPROCTOR_FILES: dict[str, str] = {
    "Benchmarks/quicktest/typescript/benchproctor-typescript-quicktest-2026.07.22.zip": "80f417b0d7aa7dbaa5ab25898a9be559484a411c46c287a0c828f6df415859c4",
    "Benchmarks/quicktest/javascript/benchproctor-javascript-quicktest-2026.07.22.zip": "ce18f02c168f5bcf97674fa62428d70bebf67942ab5fcccd4f231cf37e9d3a3e",
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


def benchproctor_dir(root: Path | None = None) -> Path:
    """Where the key's files are: `<root>/benchproctor/<commit>`."""
    return (root or answer_keys_dir()) / BENCHPROCTOR / BENCHPROCTOR_COMMIT


def benchproctor_bundle(language: str, root: Path | None = None) -> Path:
    """Where one language's bundle is extracted: `<key>/extracted/<language>`."""
    return benchproctor_dir(root) / "extracted" / language


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


def extract_zip(archive: Path, dest: Path) -> list[str]:
    """Every file entry of `archive` under `dest`, a backslash read as a
    separator (BenchProctor's bundles were made on Windows). Refused whole, with
    nothing written, when any entry would land outside `dest`."""
    with zipfile.ZipFile(archive) as bundle:
        entries = [entry for entry in bundle.infolist() if not entry.is_dir()]
        outside = [e.filename for e in entries if relative_path_problem(e.filename)]
        if outside:
            return [
                f"{archive.name}: refused, entries outside its directory: {outside[:3]}"
            ]
        for entry in entries:
            target = dest / entry.filename.replace("\\", "/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(entry))
    return []


def benchproctor(root: Path | None = None) -> list[str]:
    """BenchProctor's two quicktest bundles at the pinned commit, extracted; the
    problems met, none when both are in place. A bundle is extracted again only
    when its marker does not name the pinned hash."""
    dest = benchproctor_dir(root)
    problems = _fetch_pinned(
        dest, BENCHPROCTOR_COMMIT, BENCHPROCTOR_URL, BENCHPROCTOR_FILES
    )
    if problems:
        return problems
    for path, expected in BENCHPROCTOR_FILES.items():
        language = path.split("/")[2]
        out = benchproctor_bundle(language, root)
        marker = out.with_name(f"{language}.extracted")
        if marker.is_file() and marker.read_bytes().decode() == expected:
            continue
        shutil.rmtree(out, ignore_errors=True)
        refused = extract_zip(dest / path, out)
        if refused:
            shutil.rmtree(out, ignore_errors=True)
            problems += refused
        else:
            marker.write_bytes(expected.encode())
    return problems


KEYS: dict[str, Callable[[], list[str]]] = {
    SCA_KITCHEN_SINK: sca_kitchen_sink,
    VIBEPROOF: vibeproof,
    KICS: kics,
    ZIZMOR: zizmor,
    BENCHPROCTOR: benchproctor,
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
