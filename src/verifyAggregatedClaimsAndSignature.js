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

function extractJsonIntegerField(rawJson, fieldName) {
  const regex = new RegExp(`"${fieldName}"\\s*:\\s*(\\d+)`);
  const match = rawJson.match(regex);
  if (!match) {
    throw new Error(`Could not extract integer field "${fieldName}" from STARK proof JSON`);
  }
  return BigInt(match[1]);
}

function verifyStarkProofFile(starkProofFile, numericItem, reqMeta, claimMeta) {
  ensureRustBinaryExists();

  if (!fs.existsSync(starkProofFile)) {
    throw new Error(`STARK proof file not found: ${starkProofFile}`);
  }

  const rawProof = fs.readFileSync(starkProofFile, 'utf8');

  const proofMin = extractJsonIntegerField(rawProof, 'min');
  const proofMax = extractJsonIntegerField(rawProof, 'max');
  const proofNumBits = extractJsonIntegerField(rawProof, 'num_bits');
  const proofClaimTag = extractJsonIntegerField(rawProof, 'claim_tag');
  const proofLeafDigest = extractJsonIntegerField(rawProof, 'leaf_digest');

  const expectedMin = encodeBound(reqMeta.min, claimMeta.scale);
  const expectedMax = encodeBound(reqMeta.max, claimMeta.scale);
  const expectedNumBits = BigInt(numericItem.num_bits);
  const expectedClaimTag = BigInt(numericItem.claim_tag);
  const expectedLeafDigest = BigInt(`0x${numericItem.leaf_digest}`);

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
    throw new Error(
      `STARK proof leaf_digest mismatch for ${reqMeta.claim}: expected ${expectedLeafDigest.toString()} got ${proofLeafDigest.toString()}`
    );
  }

  const res = spawnSync(STARK_PROVER_BIN, ['verify', '--proof', starkProofFile], {
    encoding: 'utf8'
  });

  if (res.status !== 0) {
    throw new Error(
      `STARK verification failed for ${reqMeta.claim}\nSTDOUT:\n${res.stdout}\nSTDERR:\n${res.stderr}`
    );
  }

  return true;
}

async function verifySingleAggregatedClaim(revealedClaims, rootSignatureFilePath, publicKeyFilePath, requiredClaimsFilePath, claimTags) {
    // Initialize the BLS library
   
    var bls = await loadBls();
  
    // Read and parse the root and signature file
    const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));
    const requiredClaims  = JSON.parse(fs.readFileSync(requiredClaimsFilePath, 'utf8'));

    // Read and parse the public key file
    const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
    const publicKeyHex = publicKeyData.publicKey;
    const publicKey = bls.G1Element.from_bytes(Buffer.from(publicKeyHex, 'hex'));

    const disclosedGroup = revealedClaims[0] || {};
    const numericGroup = revealedClaims[1] || {};
   
    // Verify each claim
    let isValidClaims = true;
    for (const [key, item] of Object.entries(disclosedGroup)) {
      let { value, salt, proof } = item;
      if (!salt) {
        isValidClaims = false;
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
      let validTree =  await verifyProof(leaf, proof, merkleRoot);
      if (!validTree) {
        isValidClaims = false;
        break;
      }
    }
    if (isValidClaims) {
      for (const [key, item] of Object.entries(numericGroup)) {
        const reqMeta = requiredClaims.numericalClaims.find(x => x.claim === key);
        if (!reqMeta) {
          isValidClaims = false;
          break;
        }

        const claimMeta = getClaimMeta(key, claimTags);

        const validTree = await verifyProof(item.leaf_digest, item.proof, merkleRoot);
        if (!validTree) {
          isValidClaims = false;
          break;
        }

        const expectedEncodedMin = encodeBound(reqMeta.min, claimMeta.scale).toString();
        const expectedEncodedMax = encodeBound(reqMeta.max, claimMeta.scale).toString();

        if (String(item.claim_tag) !== String(claimMeta.claim_tag)) {
          isValidClaims = false;
          break;
        }
        if (String(item.scale) !== String(claimMeta.scale)) {
          isValidClaims = false;
          break;
        }
        if (String(item.encoded_min) !== expectedEncodedMin) {
          isValidClaims = false;
          break;
        }
        if (String(item.encoded_max) !== expectedEncodedMax) {
          isValidClaims = false;
          break;
        }

        verifyStarkProofFile(item.stark_proof_file, item, reqMeta, claimMeta);
      }
    }

  // Verify the signature
  const isValidSignature = bls.AugSchemeMPL.verify(
    publicKey,
    merkleRoot,
    bls.G2Element.from_bytes(Buffer.from(signature, 'hex'))
  );

  return isValidClaims && isValidSignature;
  
}

async function verifyAggregatedClaimsAndSignature(aggregatedFilePath, publicKeyFiles, rootSignatureFiles, requiredClaimsFiles) {
    // Initialize the BLS library


    var bls = await loadBls();
    const claimTags = loadClaimTags();
    // Read the aggregated claims and signature
    const { aggregatedClaims, aggregatedSignature } = JSON.parse(fs.readFileSync(aggregatedFilePath, 'utf8'));
    const aggregatedSignatureBytes = Buffer.from(aggregatedSignature, 'hex');
    const aggregatedSignatures = bls.G2Element.from_bytes(aggregatedSignatureBytes)
    
    //Check each single validity
    for (let i = 0; i < rootSignatureFiles.length; i++) {
        const isValidClaim = await verifySingleAggregatedClaim(aggregatedClaims[i], rootSignatureFiles[i], publicKeyFiles[i], requiredClaimsFiles[i], claimTags);
        console.log(`Verification of claim and signature ${i + 1}: ${isValidClaim}`);
    }
    
    // Aggregate all public keys
    let publicKeys = [];
    for (const filePath of publicKeyFiles) {
        const { publicKey } = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const publicKeyBytes = bls.G1Element.from_bytes(Buffer.from(publicKey, 'hex'));
        publicKeys.push(publicKeyBytes);
    }

    // Aggregate all roots for final verification
    let roots = [];
    for (const filePath of rootSignatureFiles) {
        const { merkleRoot } = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        roots.push(merkleRoot);
    }

    // Verify the aggregated signature with the aggregated public key
    const isValid = bls.AugSchemeMPL.aggregate_verify(publicKeys, roots, aggregatedSignatures);

    console.log(`Aggregated signature verification result: ${isValid}`);
}

export default verifyAggregatedClaimsAndSignature;