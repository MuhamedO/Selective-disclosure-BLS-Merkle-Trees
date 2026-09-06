import loadBls from "bls-signatures";
import { buildPoseidonTree } from './poseidonMerkle.js';
import fs from 'fs';
import path from 'path';
import { randomBytes } from 'crypto';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js';
import { stringToBigInt } from './utils.js';
import {
  computeLeafDigestHexFromEncoded,
  encodeNumericClaimValue,
  getClaimMeta,
  isStarkNumericClaim,
  loadClaimTags,
} from './starkLeaf.js';
import { performance } from 'perf_hooks';

const CommitmentUtils = bulletproofs.CommitmentUtils;
const PedGeneratorParams = bulletproofs.PedGeneratorParams;
const Rand = bulletproofs.Rand;
const GeneratorParams = bulletproofs.GeneratorParams;
const library = "elliptic";
const curveName = "secp256k1";
const CompressedBulletproof = bulletproofs.CompressedProofs;
const ProofFactory = bulletproofs.ProofFactory;
const pedGenParams = PedGeneratorParams.generateParams(library, curveName);
const PointFn = pedGenParams.PointFn;

// Use 96-bit random blinding to stay comfortably inside Rust u128 range.
function randomBlinding() {
  return BigInt('0x' + randomBytes(12).toString('hex'));
}

async function createAndSignCredential(claimsJsonFilePath, privateKeyJsonFilePath) {
  // Initialize the BLS library
  var bls = await loadBls();

  // Read claims JSON file
  const claimsData = JSON.parse(fs.readFileSync(claimsJsonFilePath, 'utf8'));
  const claimTags = loadClaimTags();

  // === leaf_construction_ms START ===
  const _tLeaf0 = performance.now();

  const salt = Rand.randUnder(pedGenParams.n);

  const numericWitness = {};
  const claimEntries = Object.entries(claimsData);
  // Convert the claims object into an array of strings (key:value) for the leaves
  const leaves = claimEntries.map(([key, value]) => {
    if (isStarkNumericClaim(key, value, claimTags)) {
      const meta = getClaimMeta(key, claimTags);
      const blinding = randomBlinding();
      const encodedValue = encodeNumericClaimValue(value, meta.scale);

      numericWitness[key] = {
        blinding: blinding.toString(),
        encodedValue: encodedValue.toString(),
        claimTag: meta.claim_tag,
        scale: meta.scale,
      };

      return computeLeafDigestHexFromEncoded(encodedValue, meta.claim_tag, blinding);
    }

    let normalizedValue = value;
    if (typeof normalizedValue === 'string') {
      normalizedValue = stringToBigInt(normalizedValue);
    } else {
      normalizedValue = BigInt(Math.round(normalizedValue));
    }

    return PointFn.toHexString(
      CommitmentUtils.getPedersenCommitment(normalizedValue, salt, pedGenParams)
    );
  });

  const _tLeaf1 = performance.now();
  // === leaf_construction_ms END ===

  // === merkle_tree_ms START ===
  const _tTree0 = performance.now();

  // Create the Merkle tree
  const tree = await buildPoseidonTree(leaves);

  // Get the Merkle root
  const root = tree.root;

  const _tTree1 = performance.now();
  // === merkle_tree_ms END ===

  // Read private key JSON file
  const privateKeyData = JSON.parse(fs.readFileSync(privateKeyJsonFilePath, 'utf8'));
  const privateKeyHex = privateKeyData.privateKey;

  // === bls_sign_ms START ===
  const _tSign0 = performance.now();

  // Convert the private key back to a BLS PrivateKey object
  const privateKey = bls.PrivateKey.fromBytes(Buffer.from(privateKeyHex, 'hex'), false);

  const signature = bls.AugSchemeMPL.sign(privateKey, root);
  // Sign the root with the private key
  //const signature = privateKey.sign(Buffer.from(root, 'hex'));

  // Convert the signature to hexadecimal for storage
  const signatureHex = bls.Util.hex_str(signature.serialize());

  const _tSign1 = performance.now();
  // === bls_sign_ms END ===

  // Prepare the output JSON object
  const output = {
    issuer: privateKeyData.issuer,
    merkleRoot: root,
    signature: signatureHex
  };

  const output2 = {
    claims: claimsData,
    issuer: privateKeyData.issuer,
    salt: salt.toString(),
    numericWitness
  };

  // Write the output to a JSON file
  const outputFilename = `${privateKeyData.issuer.replace(/[^a-z0-9]/gi, '_')}_${path.parse(claimsJsonFilePath).name}_signature.json`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');
  
  const outputFilename2 = `${privateKeyData.issuer.replace(/[^a-z0-9]/gi, '_')}_${path.parse(claimsJsonFilePath).name}_issued_credential.json`;
  fs.writeFileSync(outputFilename2, JSON.stringify(output2, null, 2), 'utf8');

  console.log(`Merkle root signed. Output saved to ${outputFilename}. Credential saved to ${outputFilename2}`);

  // --- Metrics ---
  const leaf_construction_ms = _tLeaf1 - _tLeaf0;
  const merkle_tree_ms       = _tTree1 - _tTree0;
  const bls_sign_ms          = _tSign1 - _tSign0;

  const metrics = {
    phase: 'issuance',
    leaf_construction_ms,
    merkle_tree_ms,
    bls_sign_ms,
    total_issuance_ms: leaf_construction_ms + merkle_tree_ms + bls_sign_ms
  };

  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tag = `${privateKeyData.issuer}_${path.parse(claimsJsonFilePath).name}`;
    fs.writeFileSync(path.join(dir, `issuance_${tag}_metrics.json`), JSON.stringify(metrics, null, 2), 'utf8');
  }

}

export default createAndSignCredential;