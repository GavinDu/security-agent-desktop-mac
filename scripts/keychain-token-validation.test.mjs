import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('Keychain token format is checked before trusted agent startup (#195)', async () => {
  const src = await readFile('src-tauri/src/secrets.rs', 'utf8');
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  assert.match(src, /const API_TOKEN_BYTES: usize = 32;/);
  assert.match(src, /const API_TOKEN_TEXT_BYTES: usize = 43;/);
  assert.match(src, /URL_SAFE_NO_PAD\.decode\(token\)/);
  assert.match(src, /bytes\.len\(\) == API_TOKEN_BYTES && URL_SAFE_NO_PAD\.encode\(bytes\) == token/);
  assert.match(src, /Ok\(token\) if canonical_api_token\(&token\) => return Ok\(token\)/);
  assert.match(src, /Ok\(_\) => return Err\("Invalid existing API token in Keychain"\.into\(\)\)/);
  assert.match(src, /OsRng\.fill_bytes\(&mut entropy\)/);
  assert.match(src, /keyring::Entry::new\("com\.gavindu\.securityagent\.desktop", "agent-api-token"\)/);
  const read = src.indexOf('match entry.get_password()');
  const write = src.indexOf('.set_password(&token)');
  assert.ok(read > 0 && write > read);
  assert.ok(src.indexOf('canonical_api_token(&token)', read) < write);
  assert.doesNotMatch(src, /Refusing a short existing API token/);
  const get = app.indexOf('secrets::get_or_create_api_token()');
  const state = app.indexOf('AgentState::new(token, bind, settings)');
  assert.ok(get > 0 && state > get);
});

test('canonical Keychain readback has native negative encoding tests (#195)', async () => {
  const src = await readFile('src-tauri/src/secrets.rs', 'utf8');
  assert.match(src, /fn canonical_api_token_requires_exact_generated_256_bit_encoding\(/);
  assert.match(src, /fn new_token_encoding_has_the_same_keychain_readback_shape\(/);
  assert.match(src, /last_index \^ 1/);
  assert.match(src, /canonical_api_token\(&noncanonical\)/);
  assert.match(src, /canonical_api_token\(&\(valid\.clone\(\) \+ "="\)\)/);
  const docs = await readFile('docs/KEYCHAIN_TOKEN_VALIDATION.md', 'utf8');
  assert.match(docs, /#37/);
  assert.match(docs, /#55/);
  assert.match(docs, /rotation/i);
});
