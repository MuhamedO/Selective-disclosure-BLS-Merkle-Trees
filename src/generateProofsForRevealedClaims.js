import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';
import bulletproofs from '@latticelabs/zkp-js/bulletproof.js'
import { closestPowerOfTwo, stringToBigInt } from './utils.js';
import path from 'path';
import { performance } from 'perf_hooks';
const CommitmentUtils = bulletproofs.CommitmentUtils;
const PedGeneratorParams = bulletproofs.PedGeneratorParams;
const Rand = bulletproofs.Rand;
const GeneratorParams = bulletproofs.GeneratorParams;
const library = "elliptic"
const curveName = "secp256k1";
const CompressedBulletproof = bulletproofs.CompressedProofs;
const ProofFactory = bulletproofs.ProofFactory;
const pedGenParams = PedGeneratorParams.generateParams(library, curveName);
const PointFn = pedGenParams.PointFn;


function generateProofsForRevealedClaims(claimsJsonFilePath, revealedClaimsFilePath) {
  // Convert the claims object into an array of strings (key:value) for the leaves
   // Read claims JSON file
   const claimsData = JSON.parse(fs.readFileSync(claimsJsonFilePath, 'utf8'));
   const revealedClaims = JSON.parse(fs.readFileSync(revealedClaimsFilePath, 'utf8'));
   // === total_disclosure_ms START ===
   const _tTotal0 = performance.now();
   // Convert the claims object into an array of strings (key:value) for the leaves
  
   const leaves = Object.entries(claimsData.claims).map(([key, value]) =>{
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
      value = BigInt(Math.round(value))
    return PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, BigInt(claimsData.salt),pedGenParams))
    }
  );
  // Create the Merkle tree
  const tree = new MerkleTree(leaves, sha256, { sortPairs: true });
  // === textual_disclosure_ms START ===
  const _tText0 = performance.now();
  // Generate proofs for the revealed claims
  const proofs = revealedClaims.disclosedClaims?.reduce((acc, claimKey) => {
    const claimValue = claimsData.claims[claimKey];
    var value = claimValue;
    if (typeof value === 'string')
      value = stringToBigInt(value)
    else 
    value = BigInt(Math.round(value));
    var salt = BigInt(claimsData.salt)
    const claimString= PointFn.toHexString(CommitmentUtils.getPedersenCommitment(value, salt,pedGenParams))
    const proof = tree.getProof(claimString).map(p => ({
      position: p.position,
      data: p.data.toString('hex')
    }));
    
    // Store the claim and its proof
    acc[claimKey] = {
      value: claimValue,
      salt: salt.toString(),
      proof
    };

    return acc;
  }, {});
  const _tText1 = performance.now();
  // === textual_disclosure_ms END ===

  // === numeric_disclosure_ms START ===
  const _tNum0 = performance.now();
  const perNumericClaimMs = {};

  const numericProof = revealedClaims.numericalClaims?.reduce((acc, claimKey) => {
    const _tClaim0 = performance.now();
    const claimValue = claimsData.claims[claimKey.claim];
    var value = claimValue;
    if (typeof value === 'string')
      value = CommitmentUtils.getPedersenCommitment(stringToBigInt(value),BigInt(claimsData.salt),pedGenParams)
    else 
      value =CommitmentUtils.getPedersenCommitment(BigInt(Math.round(value)), BigInt(claimsData.salt),pedGenParams)
    const claimString=  PointFn.toHexString(value)
    const proof = tree.getProof(claimString).map(p => ({
      position: p.position,
      data: p.data.toString('hex')
    }));

    const size = BigInt(closestPowerOfTwo(claimKey.max))
    const genParams = GeneratorParams.generateParams(size, library, curveName, pedGenParams);
    const subResult = CommitmentUtils.getPedersenCommitment(BigInt(Math.round(claimValue))- BigInt(claimKey.min), BigInt(claimsData.salt)- BigInt(revealedClaims.salt), pedGenParams);
    const subResult2 = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.max)- BigInt(Math.round(claimValue)), BigInt(revealedClaims.salt)- BigInt(claimsData.salt), pedGenParams);
    const uncompr_proof = ProofFactory.computeBulletproof(BigInt(Math.round(claimValue)) - BigInt(claimKey.min),  BigInt(claimsData.salt)- BigInt(revealedClaims.salt),  subResult, genParams, 0n, size,  false);
    const uncompr_proof2 = ProofFactory.computeBulletproof(BigInt(claimKey.max)- BigInt(Math.round(claimValue)), BigInt(revealedClaims.salt)- BigInt(claimsData.salt),  subResult2, genParams, 0n, size,  false);
    const compr_proof = uncompr_proof.compressProof(genParams,false);
    const compr_proof2 = uncompr_proof2.compressProof(genParams,false);
    const proof_json = compr_proof.toJson(false, PointFn);
    const proof_json2 = compr_proof2.toJson(false, PointFn);


    // Store the claim and its proof
    acc[claimKey.claim] = {
      value: claimString,
      proof,
      numerical_proof_low: proof_json,
      numerical_proof_high: proof_json2,
      numerical_value_low:  PointFn.toHexString(subResult),
      numerical_value_high:  PointFn.toHexString(subResult2)
    };

    const _tClaim1 = performance.now();
    perNumericClaimMs[claimKey.claim] = _tClaim1 - _tClaim0;

    return acc;
  }, {});

  const _tNum1 = performance.now();
  // === numeric_disclosure_ms END ===

  const _tTotal1 = performance.now();
  // === total_disclosure_ms END ===
  
  // Prepare the output object
  const output = {
    revealedClaims: [proofs,numericProof]
  };

  // Write the output to a JSON file
  const outputFilename = `revealedClaims_${claimsJsonFilePath.replace(/^.*[\\/]/, '')}`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');

  console.log(`Revealed claims and their proofs have been saved to ${outputFilename}`);

  // --- Metrics ---
  const metrics = {
    phase: 'disclosure',
    textual_disclosure_ms: _tText1 - _tText0,
    numeric_disclosure_ms: _tNum1 - _tNum0,
    per_numeric_claim_ms: perNumericClaimMs,
    total_disclosure_ms: _tTotal1 - _tTotal0
  };

  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const tag = claimsJsonFilePath.replace(/^.*[\\/]/, '').replace('.json', '');
    fs.writeFileSync(path.join(dir, `disclosure_${tag}_metrics.json`), JSON.stringify(metrics, null, 2), 'utf8');
  }

  // --- Size metrics ---
  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    const revealedClaimsBytes = Buffer.byteLength(JSON.stringify(output), 'utf8');
    const numericPortionBytes = numericProof ? Buffer.byteLength(JSON.stringify(numericProof), 'utf8') : 0;
    const sizeMetrics = {
      phase: 'disclosure_sizes',
      revealed_claims_total_bytes: revealedClaimsBytes,
      numeric_proof_portion_bytes: numericPortionBytes
    };
    fs.writeFileSync(path.join(dir, `disclosure_sizes_${claimsJsonFilePath.replace(/^.*[\\/]/, '').replace('.json', '')}_metrics.json`), JSON.stringify(sizeMetrics, null, 2), 'utf8');
  }
}


export default generateProofsForRevealedClaims;