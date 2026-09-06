import loadBls from "bls-signatures";
import { verifyProof } from './poseidonMerkle.js';
import fs from 'fs';
import { spawnSync } from 'child_process';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js';
import { stringToBigInt } from './utils.js';
import {
  encodeBound,
  getClaimMeta,
  loadClaimTags,
} from './starkLeaf.js';
import path from 'path';
import { randomBytes } from 'crypto';
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

const STARK_PROVER_BIN =
  process.env.STARK_PROVER_BIN ||
  path.resolve(process.cwd(), 'stark_range_prover.exe');

function ensureRustBinaryExists() {
  if (!fs.existsSync(STARK_PROVER_BIN)) {
    throw new Error(`STARK prover binary not found at ${STARK_PROVER_BIN}`);
  }
}

function assertDigits(value, fieldName) {
  const str = String(value);
  if (!/^\d+$/.test(str)) {
    throw new Error(`Invalid numeric string for ${fieldName}: ${value}`);
  }
  return str;
}

function assertHex(value, fieldName) {
  const str = String(value);
  if (!/^[0-9a-fA-F]+$/.test(str)) {
    throw new Error(`Invalid hex string for ${fieldName}`);
  }
  return str;
}

function writeTempStarkProofFile(starkProof) {
  const proofBytesHex = assertHex(starkProof.proof_bytes_hex, 'proof_bytes_hex');

  const min = assertDigits(starkProof.pub_inputs.min, 'min');
  const max = assertDigits(starkProof.pub_inputs.max, 'max');
  const numBits = assertDigits(starkProof.pub_inputs.num_bits, 'num_bits');
  const claimTag = assertDigits(starkProof.pub_inputs.claim_tag, 'claim_tag');
  const leafDigest = assertDigits(starkProof.pub_inputs.leaf_digest, 'leaf_digest');

  const tempFilePath = path.resolve(
    process.cwd(),
    `.tmp_stark_proof_${Date.now()}_${randomBytes(4).toString('hex')}.json`
  );

  const rawJson = `{
  "proof_bytes_hex": "${proofBytesHex}",
  "pub_inputs": {
    "min": ${min},
    "max": ${max},
    "num_bits": ${numBits},
    "claim_tag": ${claimTag},
    "leaf_digest": ${leafDigest}
  }
}`;

  fs.writeFileSync(tempFilePath, rawJson, 'utf8');
  return tempFilePath;
}

function bitLengthBigInt(n) {
  let x = BigInt(n);
  if (x < 0n) x = -x;
  if (x === 0n) return 1;
  return x.toString(2).length;
}

function nextPowerOfTwoInt(n) {
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

function computeExpectedNumBits(encodedMin, encodedMax) {
  const rangeWidth = encodedMax - encodedMin;
  if (rangeWidth < 0n) {
    throw new Error('Invalid numeric range: min > max');
  }
  const neededBits = bitLengthBigInt(rangeWidth);
  return BigInt(nextPowerOfTwoInt(neededBits));
}

function verifyStarkProofObject(starkProof, leafDigestHex, reqMeta, claimMeta) {
  ensureRustBinaryExists();

  if (!starkProof || !starkProof.pub_inputs) {
    throw new Error(`Missing embedded STARK proof for ${reqMeta.claim}`);
  }

  const proofMin = BigInt(starkProof.pub_inputs.min);
  const proofMax = BigInt(starkProof.pub_inputs.max);
  const proofNumBits = BigInt(starkProof.pub_inputs.num_bits);
  const proofClaimTag = BigInt(starkProof.pub_inputs.claim_tag);
  const proofLeafDigest = BigInt(starkProof.pub_inputs.leaf_digest);

  const expectedMin = encodeBound(reqMeta.min, claimMeta.scale);
  const expectedMax = encodeBound(reqMeta.max, claimMeta.scale);
  const expectedNumBits = computeExpectedNumBits(expectedMin, expectedMax);
  const expectedClaimTag = BigInt(claimMeta.claim_tag);
  const expectedLeafDigest = BigInt(`0x${leafDigestHex}`);

  if (proofMin !== expectedMin) {
    throw new Error(`STARK proof min mismatch for ${reqMeta.claim}`);
  }
  if (proofMax !== expectedMax) {
    throw new Error(`STARK proof max mismatch for ${reqMeta.claim}`);
  }
  if (proofNumBits !== expectedNumBits) {
    throw new Error(`STARK proof num_bits mismatch for ${reqMeta.claim}`);
  }
  if (proofClaimTag !== expectedClaimTag) {
    throw new Error(`STARK proof claim_tag mismatch for ${reqMeta.claim}`);
  }
  if (proofLeafDigest !== expectedLeafDigest) {
    throw new Error(`STARK proof leaf_digest mismatch for ${reqMeta.claim}`);
  }

  const tempProofFile = writeTempStarkProofFile(starkProof);

  try {
    const res = spawnSync(STARK_PROVER_BIN, ['verify', '--proof', tempProofFile], {
      encoding: 'utf8'
    });

    if (res.status !== 0) {
      throw new Error(
        `STARK verification failed for ${reqMeta.claim}\nSTDOUT:\n${res.stdout}\nSTDERR:\n${res.stderr}`
      );
    }
  } finally {
    if (fs.existsSync(tempProofFile)) {
      fs.unlinkSync(tempProofFile);
    }
  }

  return true;
}

async function verifyClaims(proofsFilePath, rootSignatureFilePath, publicKeyFilePath, requiredClaimsFilePath) {
  // Initialize the BLS library
  var bls = await loadBls();

  // Read and parse the proofs file
  const { revealedClaims } = JSON.parse(fs.readFileSync(proofsFilePath, 'utf8'));
  const requiredClaims = JSON.parse(fs.readFileSync(requiredClaimsFilePath, 'utf8'));

  // Read and parse the root and signature file
  const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));

  // Read and parse the public key file
  const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
  const claimTags = loadClaimTags();
  const publicKeyHex = publicKeyData.publicKey;
  const publicKey = bls.G1Element.from_bytes(Buffer.from(publicKeyHex, 'hex'));

  const disclosedGroup = revealedClaims[0] || {};
  const numericGroup = revealedClaims[1] || {};

  // === total_verify_ms START ===
  const _tTotal0 = performance.now();
  let textualVerifyMs = 0;
  let numericVerifyMs = 0;
 
  // Verify each claim
  let isValidClaims = true;

  for (const [key, item] of Object.entries(disclosedGroup)) {
    const _tTx0 = performance.now();
    let { value, salt, proof } = item;
    if (!salt) {
      isValidClaims = false;
      const _tTx1 = performance.now();
      textualVerifyMs += _tTx1 - _tTx0;
      break;
    }
    let normalizedValue = value;
    if (typeof normalizedValue === 'string') {
      normalizedValue = stringToBigInt(normalizedValue);
    } else {
      normalizedValue = BigInt(Math.round(normalizedValue));
    }

    const leaf = PointFn.toHexString(
      CommitmentUtils.getPedersenCommitment(normalizedValue, BigInt(salt), pedGenParams)
    );
    let validTree = await verifyProof(leaf, proof, merkleRoot);

    const _tTx1 = performance.now();
    textualVerifyMs += _tTx1 - _tTx0;

    if (!validTree) {
      isValidClaims = false;
      break;
    }
  } 
  if (isValidClaims) {
    for (const [key, item] of Object.entries(numericGroup)) {
      const _tNm0 = performance.now();

      const reqMeta = requiredClaims.numericalClaims.find(x => x.claim === key);
      if (!reqMeta) {
        isValidClaims = false;
        const _tNm1 = performance.now();
        numericVerifyMs += _tNm1 - _tNm0;
        break;
      }
      const claimMeta = getClaimMeta(key, claimTags);

      const validTree = await verifyProof(item.leaf_digest, item.proof, merkleRoot);
      if (!validTree) {
        isValidClaims = false;
        const _tNm1 = performance.now();
        numericVerifyMs += _tNm1 - _tNm0;
        break;
      }

      verifyStarkProofObject(item.stark_proof, item.leaf_digest, reqMeta, claimMeta);

      const _tNm1 = performance.now();
      numericVerifyMs += _tNm1 - _tNm0;
    }
  }

  // === bls_verify_ms START ===
  const _tBls0 = performance.now();

  // Verify the signature
  const isValidSignature = bls.AugSchemeMPL.verify(
    publicKey,
    merkleRoot,
    bls.G2Element.from_bytes(Buffer.from(signature, 'hex'))
  );

  const _tBls1 = performance.now();
  // === bls_verify_ms END ===

  const _tTotal1 = performance.now();
  // === total_verify_ms END ===

  console.log(`Claims are valid: ${isValidClaims}`);
  console.log(`Signature is valid: ${isValidSignature}`);

  // --- Metrics ---
  const metrics = {
    phase: 'verify',
    textual_verify_ms: textualVerifyMs,
    numeric_verify_ms: numericVerifyMs,
    bls_verify_ms: _tBls1 - _tBls0,
    total_verify_ms: _tTotal1 - _tTotal0
  };

  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tag = proofsFilePath.replace(/^.*[\\/]/, '').replace('.json', '');
    fs.writeFileSync(path.join(dir, `verify_${tag}_metrics.json`), JSON.stringify(metrics, null, 2), 'utf8');
  }
}

export default verifyClaims;