/**
 * One-time, exact-head branch retirement. Issue #162, successor Epic #10.
 * On main only; no user-provided branch names or arbitrary ref deletion.
 * Closed-unmerged PRs additionally require trusted on-disk equivalence evidence.
 */
import { readFile } from 'node:fs/promises';

export const verifiedCandidates = [
  {
    "name": "chore/macos-queue-telemetry-r05",
    "pr": 71,
    "status": "merged",
    "sha": "8fae2a43e4b7ad5963e508abf4a2bf47af2dc840"
  },
  {
    "name": "ci/143-gate-native-macos-on-source",
    "pr": 144,
    "status": "merged",
    "sha": "c406d2a565d06124917934bd06ff9d36ba607c6c"
  },
  {
    "name": "feat/foundation-entitlement-policy-evidence",
    "pr": 63,
    "status": "merged",
    "sha": "b82c72cc2592deb46c67d57dd1d4146b7dccbe27"
  },
  {
    "name": "feat/foundation-single-process-guard",
    "pr": 67,
    "status": "merged",
    "sha": "a0b7609b1d93b84cb059440aa720794deb7cf559"
  },
  {
    "name": "feat/foundation-smoke-root-audit",
    "pr": 65,
    "status": "merged",
    "sha": "f1feb9564e8e9aa1f7cd665ef8aef6f5012b14ba"
  },
  {
    "name": "feat/tauri-axum-wireguard-scaffold",
    "pr": 1,
    "status": "merged",
    "sha": "872923eef4d4d92b5934861093ed47648ec17c4c"
  },
  {
    "name": "fix/macos-native-reopen-focus-72",
    "pr": 73,
    "status": "merged",
    "sha": "1bf084214afc13e0ae5121d0ce67c69f6ed9dbc4"
  },
  {
    "name": "fix/macos-queue-pr-sha-70",
    "pr": 78,
    "status": "merged",
    "sha": "f6585de78a9758fdc01ce498d25f17605de8a389"
  },
  {
    "name": "fix/127-pin-instance-lock-directory-fd",
    "pr": 128,
    "status": "merged",
    "sha": "def85ef6b46dd7e5af4466b0cf748a3fa54c31dd"
  },
  {
    "name": "security/approval-cancellation-cleanup-113",
    "pr": 114,
    "status": "merged",
    "sha": "78c514474ba7ede4ef7a4fde95b9ed9cb836cf02"
  },
  {
    "name": "security/atomic-root-grant-update-117",
    "pr": 118,
    "status": "merged",
    "sha": "93456883613aab93f37e504de6893174aca161ae"
  },
  {
    "name": "security/atomic-tool-policy-persistence-123",
    "pr": 124,
    "status": "merged",
    "sha": "5cfd5d768aae8e6a39cbf452d69225860afdb58c"
  },
  {
    "name": "security/axum-json-body-cap-83",
    "pr": 84,
    "status": "merged",
    "sha": "f78f8f0202634a623b04c704c59147447b21f713"
  },
  {
    "name": "security/bounded-shell-output-91",
    "pr": 92,
    "status": "merged",
    "sha": "0dee24aa14b3d093f1ea66737fd1f4cb96462de0"
  },
  {
    "name": "security/ci-checkout-identity-89",
    "pr": 90,
    "status": "merged",
    "sha": "e9b2330c982670ee73aa9f3c1ad3fa943cbfff04"
  },
  {
    "name": "security/constructor-bind-allowlist-104",
    "pr": 105,
    "status": "superseded",
    "sha": "9b08526c0a2b0cffd1df8f7f684f83479cabd094"
  },
  {
    "name": "security/dmg-inventory-strict-85",
    "pr": 86,
    "status": "merged",
    "sha": "4479b4beecc1811b24ef51fd69998ae9f63a561f"
  },
  {
    "name": "security/foundation-settings-smoke-fd-96",
    "pr": 97,
    "status": "superseded",
    "sha": "ec1122a46fb367df44c4036eaaeb82bcfad00931"
  },
  {
    "name": "security/instance-lock-nofollow-79",
    "pr": 80,
    "status": "merged",
    "sha": "99d76d4967f17e3c5d886d7702d39cfaf78df939"
  },
  {
    "name": "security/keychain-backend-error-redaction-109",
    "pr": 110,
    "status": "merged",
    "sha": "e74c78aef12767f9cc450883806af7fb844bd7ee"
  },
  {
    "name": "security/pinned-grant-dirfd-openat-115",
    "pr": 116,
    "status": "merged",
    "sha": "59c7ef2ce86e275611648d24e5945fa0a2f54997"
  },
  {
    "name": "security/post-approval-reauthorization-121",
    "pr": 122,
    "status": "merged",
    "sha": "2f785f0ec3e3e1ddc2db37606a5b4357e5825466"
  },
  {
    "name": "security/redact-root-errors-98",
    "pr": 99,
    "status": "merged",
    "sha": "0eca08bc60d67e306e9275a6927234ace86bdf9a"
  },
  {
    "name": "security/reject-empty-bearer-token-102",
    "pr": 103,
    "status": "superseded",
    "sha": "2aaab2024c57cd182f572e7d40289572f1abdf7c"
  },
  {
    "name": "security/remote-shell-fail-closed-111",
    "pr": 112,
    "status": "merged",
    "sha": "024c36d0176c50a6c642d1d6120be1d18f4ab9be"
  },
  {
    "name": "security/require-adhoc-mounted-dmg-signature-119",
    "pr": 120,
    "status": "merged",
    "sha": "964796d073ec776e8f33ce6736e7d5c8b9a46311"
  },
  {
    "name": "security/scoped-file-descriptor-94",
    "pr": 95,
    "status": "merged",
    "sha": "a96bdfe96af1baa150c20b3dcab5065d89a3ddc2"
  },
  {
    "name": "security/settings-verified-load-87",
    "pr": 88,
    "status": "merged",
    "sha": "c307e477ef9f37172283f4adc3e428351afab96d"
  },
  {
    "name": "security/shell-process-group-owner-93",
    "pr": 107,
    "status": "merged",
    "sha": "a6ca1e46b0a3e911fccd13818c3d7dcf39e39cad"
  },
  {
    "name": "security/smoke-keychain-fixed-binary-81",
    "pr": 82,
    "status": "superseded",
    "sha": "3d830252cbdabf422ee597eb4102f4d9fa154738"
  },
  {
    "name": "security/tool-dispatch-concurrency-100",
    "pr": 101,
    "status": "merged",
    "sha": "7e896c61739b8c1e43a98130907e0bc958343207"
  },
  {
    "name": "security/ui-policy-single-flight-125",
    "pr": 126,
    "status": "merged",
    "sha": "d85681e05c5589a51c974f214215f9d9eaea3a01"
  },
  {
    "name": "security/129-reject-elevated-desktop-uid",
    "pr": 130,
    "status": "merged",
    "sha": "5a783a94a1a97d401d6b3e101d4a147c86c6180c"
  },
  {
    "name": "security/131-trusted-webview-no-fragments",
    "pr": 132,
    "status": "merged",
    "sha": "16619c264f93c8424036ce95ba6b865c085e68c7"
  },
  {
    "name": "security/133-peer-rate-limit",
    "pr": 134,
    "status": "merged",
    "sha": "97b7206764587cb7c5fb9d31071ff84151b61088"
  },
  {
    "name": "security/135-stale-approval-ui",
    "pr": 136,
    "status": "merged",
    "sha": "e61445558114447b02335a2b12f3901b37bd96ae"
  },
  {
    "name": "security/137-pinned-settings-directory",
    "pr": 138,
    "status": "merged",
    "sha": "9b0f00bd89fd0072b5bbe47310437438284a9b3b"
  },
  {
    "name": "security/139-cap-pending-approvals",
    "pr": 140,
    "status": "merged",
    "sha": "ff12900f63faf09de01ca4d94501ab8ecd2b06c3"
  },
  {
    "name": "security/141-strict-tool-envelope",
    "pr": 142,
    "status": "merged",
    "sha": "81d96c7a8f96254b933e79419088ebf43f0a5ded"
  },
  {
    "name": "security/145-strict-chat-envelope",
    "pr": 146,
    "status": "merged",
    "sha": "be9910336ea2b82e758d56394e86462f49960b68"
  },
  {
    "name": "security/147-redact-listener-diagnostics",
    "pr": 148,
    "status": "merged",
    "sha": "d910a75d87b177d887e78791a8ff3a2857e846ba"
  },
  {
    "name": "security/150-policy-visible-tool-catalog",
    "pr": 151,
    "status": "merged",
    "sha": "1e022d608ff3d541bbc2fc2cd08db0f2d1996c84"
  },
  {
    "name": "security/152-redact-desktop-ipc-errors",
    "pr": 153,
    "status": "merged",
    "sha": "794acfcd9906c29da65f4b27024173d3f026eaab"
  },
  {
    "name": "security/154-single-flight-root-revocation",
    "pr": 155,
    "status": "merged",
    "sha": "1023de65db396e18719f70ee0ad27f39128bb2cb"
  },
  {
    "name": "test/foundation-settings-policy-standalone",
    "pr": 69,
    "status": "superseded",
    "sha": "9a60d90cb3e13fe99af259fc700cdc669b8e19b2"
  },
  {
    "name": "test/foundation-webview-hook-regression",
    "pr": 68,
    "status": "merged",
    "sha": "aace39d53f12c34427e380417cfdec5aa6316950"
  },
  {
    "name": "test/mac-listener-smoke-74",
    "pr": 75,
    "status": "merged",
    "sha": "c34c611803beef0414aede024a704e90abbecbe6"
  },
  {
    "name": "test/release-dev-artifact-policy-76",
    "pr": 77,
    "status": "merged",
    "sha": "229a597daed608abbba3da1963ee9ce6d53b5198"
  }
];
export const supersededEvidence = {
  "69": {
    "src-tauri/src/settings.rs": [
      "atomically_saves_and_reloads_restrictive_settings",
      ".insert(\"filesystem__read_file\".into(), Policy::Auto)",
      "!reloaded.policies.contains_key(\"filesystem__read_file\")"
    ]
  },
  "82": {
    "scripts/smoke-keychain.mjs": [
      "/usr/bin/security",
      "readAgentApiToken"
    ],
    "scripts/smoke-keychain.test.mjs": [
      "Keychain lookup",
      "subprocess failures"
    ],
    "scripts/smoke-local.mjs": [
      "readAgentApiToken()"
    ]
  },
  "97": {
    "scripts/smoke-settings.mjs": [
      "O_NOFOLLOW",
      "O_NONBLOCK",
      "TextDecoder",
      "readPrivateSettings"
    ],
    "scripts/smoke-settings-secure.test.mjs": [
      "one-descriptor audit",
      "hardlinks",
      "invalid UTF-8"
    ],
    "package.json": [
      "node --test scripts/*.test.mjs"
    ]
  },
  "103": {
    "src-tauri/src/agent/mod.rs": [
      "token.trim().is_empty()",
      "unavailable_bearer_credentials_fail_closed_before_agent_setup"
    ],
    "scripts/agent-identity-dispatch.test.mjs": [
      "empty bearer token cannot reach the Axum router (#102)"
    ]
  },
  "105": {
    "src-tauri/src/agent/mod.rs": [
      "allowed_agent_bind(bind)",
      "constructor_enforces_shared_loopback_and_tunnel_bind_allowlist"
    ],
    "scripts/agent-identity-dispatch.test.mjs": [
      "share the same strict bind allowlist (#104)"
    ],
    "src-tauri/src/agent/server.rs": [
      "TcpListener::bind(\"127.0.0.1:8080\")"
    ]
  }
};

// Once both in-flight PRs merge, their source refs become independently
// deletable with the GitHub-verified exact PR head. Until then, preserve them.
export const trackedActivePRs = [
  { name: 'security/158-stale-root-snapshot-fence', pr: 161 },
  { name: 'security/156-native-root-mutation-order', pr: 163 },
];

export function eligibleForDeletion(candidate, branch, pr, activeBranches, evidenceSatisfied) {
  if (!candidate || candidate.name === 'main' || !/^[a-z0-9][a-z0-9/_-]+$/.test(candidate.name)) return false;
  if (!branch || branch.protected || branch.name !== candidate.name) return false;
  if (activeBranches.has(candidate.name) || branch.commit?.sha !== candidate.sha) return false;
  if (!pr || pr.head?.sha !== candidate.sha || pr.head?.ref !== candidate.name) return false;
  if (pr.head?.repo?.full_name !== 'GavinDu/security-agent-desktop-mac') return false;
  if (pr.state !== 'closed') return false;
  return candidate.status === 'merged'
    ? Boolean(pr.merged_at)
    : candidate.status === 'superseded' && !pr.merged_at && evidenceSatisfied;
}

export async function verifySupersededEvidence(candidate, reader = readFile) {
  if (candidate.status !== 'superseded') return true;
  const required = supersededEvidence[String(candidate.pr)];
  if (!required) return false;
  for (const [file, markers] of Object.entries(required)) {
    let contents;
    try { contents = await reader(file, 'utf8'); } catch { return false; }
    if (!markers.every(marker => contents.includes(marker))) return false;
  }
  return true;
}

async function request(repo, token, path, method = 'GET') {
  const response = await fetch('https://api.github.com/repos/' + repo + path, {
    method,
    headers: {
      Authorization: 'Bearer ' + token,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'desktop-branch-cleanup-162',
    },
  });
  if (!response.ok) throw new Error('GitHub API ' + method + ' failed with status ' + response.status);
  return response.status === 204 ? null : response.json();
}

export async function pruneVerifiedBranches(env = process.env) {
  const repo = env.GITHUB_REPOSITORY;
  if (repo !== 'GavinDu/security-agent-desktop-mac' || env.GITHUB_REF !== 'refs/heads/main') {
    throw new Error('Ref cleanup is restricted to this repository on main');
  }
  const token = env.GITHUB_TOKEN;
  if (!token) throw new Error('Missing narrowly scoped GitHub Actions token');

  const branches = await request(repo, token, '/branches?per_page=100');
  const openPRs = await request(repo, token, '/pulls?state=open&per_page=100');
  if (branches.length === 100 || openPRs.length === 100) {
    throw new Error('Ref or PR pagination needed; refusing incomplete cleanup snapshot');
  }
  const byName = new Map(branches.map(branch => [branch.name, branch]));
  const activeBranches = new Set(openPRs.filter(pr => pr.head?.repo?.full_name === repo).map(pr => pr.head.ref));
  let deleted = 0;
  let skipped = 0;
  for (const candidate of verifiedCandidates) {
    const branch = byName.get(candidate.name);
    if (!branch || activeBranches.has(candidate.name) || branch.commit.sha !== candidate.sha) {
      skipped++;
      continue;
    }
    const pr = await request(repo, token, '/pulls/' + candidate.pr);
    const evidence = await verifySupersededEvidence(candidate);
    if (!eligibleForDeletion(candidate, branch, pr, activeBranches, evidence)) {
      skipped++;
      continue;
    }
    // Freshly recheck the remote ref immediately before deleting it.
    const live = await request(repo, token, '/git/ref/heads/' + candidate.name);
    if (live.object?.sha !== candidate.sha) {
      skipped++;
      continue;
    }
    await request(repo, token, '/git/refs/heads/' + candidate.name, 'DELETE');
    deleted++;
    console.log('Pruned verified branch: ' + candidate.name + ' (PR #' + candidate.pr + ')');
  }
  // Follow-up passes also clean up the two current PR heads once merged.
  // Never infer successful merge from a closed PR alone, and never delete
  // a branch whose head differs from its actual merged PR commit.
  for (const tracked of trackedActivePRs) {
    const branch = byName.get(tracked.name);
    if (!branch || branch.protected || activeBranches.has(tracked.name)) continue;
    const pr = await request(repo, token, '/pulls/' + tracked.pr);
    const candidate = { ...tracked, sha: branch.commit.sha, status: 'merged' };
    if (!eligibleForDeletion(candidate, branch, pr, activeBranches, true)) continue;
    const live = await request(repo, token, '/git/ref/heads/' + tracked.name);
    if (live.object?.sha !== candidate.sha) continue;
    await request(repo, token, '/git/refs/heads/' + tracked.name, 'DELETE');
    deleted++;
    console.log('Pruned verified merged active branch: ' + tracked.name + ' (PR #' + tracked.pr + ')');
  }
  const remaining = await request(repo, token, '/branches?per_page=100');
  if (remaining.length === 100) throw new Error('Cannot verify full post-cleanup branch inventory');
  const featureCount = remaining.filter(branch => branch.name !== 'main').length;
  console.log('Branch audit: deleted=' + deleted + ' skipped=' + skipped + ' feature_branches=' + featureCount);
  if (featureCount > 5) throw new Error('Feature branch count still exceeds the owner limit of five');
  return { deleted, skipped, featureCount };
}

if (process.argv[1]?.endsWith('/prune-verified-branches.mjs')) {
  pruneVerifiedBranches().catch(error => {
    // Never print bearer, request bodies, or remote OS paths in failures.
    console.error('Branch cleanup stopped: ' + error.message);
    process.exitCode = 1;
  });
}
