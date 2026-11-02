import loadBls from "bls-signatures";
import { buildPoseidonTree, getProof } from './poseidonMerkle.js';
import fs from 'fs';
import { spawnSync } from 'child_process';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js';
import { stringToBigInt } from './utils.js';
import {
  computeLeafDigestHexFromEncoded,
  encodeBound,
  getClaimMeta,
  isStarkNumericClaim,
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

function extractJsonStringField(rawJson, fieldName) {
  const regex = new RegExp(`"${fieldName}"\\s*:\\s*"([^"]+)"`);
  const match = rawJson.match(regex);
  if (!match) {
    throw new Error(`Could not extract string field "${fieldName}" from STARK proof JSON`);
  }
  return match[1];
}

function extractJsonIntegerFieldAsString(rawJson, fieldName) {
  const regex = new RegExp(`"${fieldName}"\\s*:\\s*(\\d+)`);
  const match = rawJson.match(regex);
  if (!match) {
    throw new Error(`Could not extract integer field "${fieldName}" from STARK proof JSON`);
  }
  return match[1];
}

function loadEmbeddedStarkProof(proofFilePath) {
  const rawProof = fs.readFileSync(proofFilePath, 'utf8');

  return {
    proof_bytes_hex: extractJsonStringField(rawProof, 'proof_bytes_hex'),
    pub_inputs: {
      min: extractJsonIntegerFieldAsString(rawProof, 'min'),
      max: extractJsonIntegerFieldAsString(rawProof, 'max'),
      num_bits: extractJsonIntegerFieldAsString(rawProof, 'num_bits'),
      claim_tag: extractJsonIntegerFieldAsString(rawProof, 'claim_tag'),
      leaf_digest: extractJsonIntegerFieldAsString(rawProof, 'leaf_digest'),
    }
  };
}

function buildAllLeaves(claimsData, claimTags) {
  const claimEntries = Object.entries(claimsData.claims);

  const leaves = claimEntries.map(([key, value]) => {
    if (isStarkNumericClaim(key, value, claimTags)) {
      const witness = claimsData.numericWitness?.[key];
      if (!witness) {
        throw new Error(`Missing numericWitness for claim "${key}"`);
      }
      return computeLeafDigestHexFromEncoded(
        BigInt(witness.encodedValue),
        BigInt(witness.claimTag),
        BigInt(witness.blinding)
      );
    }

    let normalizedValue = value;
    if (typeof normalizedValue === 'string') {
      normalizedValue = stringToBigInt(normalizedValue);
    } else {
      normalizedValue = BigInt(Math.round(normalizedValue));
    }

    return PointFn.toHexString(
      CommitmentUtils.getPedersenCommitment(normalizedValue, BigInt(claimsData.salt), pedGenParams)
    );
  });

  return { claimEntries, leaves };
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

function generateStarkProofForClaim(claimKey, rawValue, witness, meta, reqMeta) {
  ensureRustBinaryExists();

  const encodedMin = encodeBound(reqMeta.min, meta.scale);
  const encodedMax = encodeBound(reqMeta.max, meta.scale);
  const rangeWidth = encodedMax - encodedMin;
  if (rangeWidth < 0n) {
    throw new Error(`Invalid range for ${claimKey}: min > max`);
  }
  const neededBits = bitLengthBigInt(rangeWidth);
  const bits = Math.max(8, nextPowerOfTwoInt(neededBits));
  const outFile = `${claimKey}_proof.json`;

  const args = [
    'prove',
    '--value', witness.encodedValue,
    '--min', encodedMin.toString(),
    '--max', encodedMax.toString(),
    '--claim-tag', String(witness.claimTag),
    '--blinding', witness.blinding,
    '--bits', String(bits),
    '--out', outFile,
  ];

  const res = spawnSync(STARK_PROVER_BIN, args, { encoding: 'utf8' });
  if (res.status !== 0) {
    throw new Error(`STARK prove failed for ${claimKey}\nSTDOUT:\n${res.stdout}\nSTDERR:\n${res.stderr}`);
  }

  const embeddedProof = loadEmbeddedStarkProof(outFile);

  // Delete the temporary standalone proof file now that it is embedded.
  fs.unlinkSync(outFile);

  return {
    encodedMin: encodedMin.toString(),
    encodedMax: encodedMax.toString(),
    bits,
    embeddedProof,
  };
}

async function generateProofsForRevealedClaims(claimsJsonFilePath, revealedClaimsFilePath) {
  // Convert the claims object into an array of strings (key:value) for the leaves
   // Read claims JSON file
   const claimsData = JSON.parse(fs.readFileSync(claimsJsonFilePath, 'utf8'));
   const revealedClaims = JSON.parse(fs.readFileSync(revealedClaimsFilePath, 'utf8'));
   const claimTags = loadClaimTags();
   // Convert the claims object into an array of strings (key:value) for the leaves
   const { claimEntries, leaves } = buildAllLeaves(claimsData, claimTags);
  
  const leafIndexByKey = Object.fromEntries(claimEntries.map(([key], index) => [key, index]));

  // Create the Merkle tree
  const tree = await buildPoseidonTree(leaves);
  // Generate proofs for the revealed claims
  const proofs = revealedClaims.disclosedClaims?.reduce((acc, claimKey) => {
    const claimValue = claimsData.claims[claimKey];
    if (!(claimKey in leafIndexByKey)) {
      throw new Error(`Claim "${claimKey}" not found in credential`);
    }
    var value = claimValue;
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
      value = BigInt(Math.round(value));
    
    const proof = getProof(tree, leafIndexByKey[claimKey]);
    
    // Store the claim and its proof
    acc[claimKey] = {
      value: claimValue,
      salt: BigInt(claimsData.salt).toString(),
      proof
    };

    return acc;
  }, {}) || {};
  const numericProof = revealedClaims.numericalClaims?.reduce((acc, reqMeta) => {
    const claimKey = reqMeta.claim;
    const claimValue = claimsData.claims[claimKey];
    if (!(claimKey in leafIndexByKey)) {
      throw new Error(`Numerical claim "${claimKey}" not found in credential`);
    }
    const meta = getClaimMeta(claimKey, claimTags);
    const witness = claimsData.numericWitness?.[claimKey];
    if (!witness) {
      throw new Error(`Missing numericWitness for claim "${claimKey}"`);
    }

    const leafDigest = computeLeafDigestHexFromEncoded(
      BigInt(witness.encodedValue),
      BigInt(witness.claimTag),
      BigInt(witness.blinding)
    );
    const proof = getProof(tree, leafIndexByKey[claimKey]);
    const stark = generateStarkProofForClaim(claimKey, claimValue, witness, meta, reqMeta);

    // Store the claim and its proof
    acc[claimKey] = {
      leaf_digest: leafDigest,
      proof,
      stark_proof: stark.embeddedProof,
    };

    return acc;
  }, {}) || {};

  
  // Prepare the output object
  const output = {
    revealedClaims: [proofs, numericProof]
  };

  // Write the output to a JSON file
  const outputFilename = `revealedClaims_${claimsJsonFilePath.replace(/^.*[\\/]/, '')}`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');

  console.log(`Revealed claims and their proofs have been saved to ${outputFilename}`);
}


export default generateProofsForRevealedClaims;