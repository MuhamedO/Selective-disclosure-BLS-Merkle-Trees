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

async function verifyClaims(proofsFilePath, rootSignatureFilePath, publicKeyFilePath, requiredClaimsFilePath) {
  // Initialize the BLS library
  var bls = await loadBls();

  // Read and parse the proofs file
  const { revealedClaims } = JSON.parse(fs.readFileSync(proofsFilePath, 'utf8'));
  const requiredClaims  = JSON.parse(fs.readFileSync(requiredClaimsFilePath, 'utf8'));

  // Read and parse the root and signature file
  const { merkleRoot, signature } = JSON.parse(fs.readFileSync(rootSignatureFilePath, 'utf8'));

  // Read and parse the public key file
  const publicKeyData = JSON.parse(fs.readFileSync(publicKeyFilePath, 'utf8'));
  const publicKeyHex = publicKeyData.publicKey;
  const publicKey = bls.G1Element.from_bytes(Buffer.from(publicKeyHex,'hex'));
 
  // Verify each claim
  const tree = new MerkleTree([], sha256, { sortPairs: true }); // Dummy tree for verification

  // === total_verify_ms START ===
  const _tTotal0 = performance.now();
  let textualVerifyMs = 0;
  let numericVerifyMs = 0;

  let isValidClaims = true;
  for (const claimGroup of revealedClaims) {
    for (const [key, { value, salt, proof, numerical_proof_low, numerical_proof_high, numerical_value_low, numerical_value_high }] of Object.entries(claimGroup)) {
      // === textual accumulate START ===
      const _tTx0 = performance.now();
      let leaf = value;
      if (salt) {
        let v = value;
        if (typeof v === 'string')
          v = stringToBigInt(v);
        else
          v = BigInt(Math.round(v));
        leaf = PointFn.toHexString(CommitmentUtils.getPedersenCommitment(v, BigInt(salt), pedGenParams));
      }
      const proofObjects = proof.map(p => ({ position: p.position, data: Buffer.from(p.data, 'hex') }));
      let validTree = tree.verify(proofObjects, leaf, merkleRoot);
      const _tTx1 = performance.now();
      textualVerifyMs += _tTx1 - _tTx0;
      // === textual accumulate END ===

      let validNumeric = true;
      let validRangeLow = true;
      let validRangeHigh = true;
      if (numerical_proof_low) {
        // === numeric accumulate START ===
        const _tNm0 = performance.now();

        const claimKey = requiredClaims.numericalClaims.find(x => x.claim === key);
        const size = BigInt(closestPowerOfTwo(claimKey.max));
        const genParams = GeneratorParams.generateParams(size, library, curveName, pedGenParams);
        const proof_low = CompressedBulletproof.fromJsonString(
          numerical_proof_low,
          genParams.pedGen.CurveFn,
          PointFn
        );
        const proof_high = CompressedBulletproof.fromJsonString(
          numerical_proof_high,
          genParams.pedGen.CurveFn,
          PointFn
        );

        validRangeLow = proof_low.verify(0n, size, PointFn.fromHexString(numerical_value_low, genParams.pedGen.CurveFn), genParams);
        validRangeHigh = proof_high.verify(0n, size, PointFn.fromHexString(numerical_value_high, genParams.pedGen.CurveFn), genParams);

        const mini = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.min), BigInt(requiredClaims.salt), pedGenParams);
        const maxi = CommitmentUtils.getPedersenCommitment(BigInt(claimKey.max), BigInt(requiredClaims.salt), pedGenParams);

        const sub = CommitmentUtils.comSubCom(PointFn.fromHexString(leaf, pedGenParams.CurveFn), mini, PointFn);
        const sub2 = CommitmentUtils.comSubCom(maxi, PointFn.fromHexString(leaf, pedGenParams.CurveFn), PointFn);
        validNumeric = (PointFn.toHexString(sub) === numerical_value_low) && (PointFn.toHexString(sub2) === numerical_value_high);

        const _tNm1 = performance.now();
        numericVerifyMs += _tNm1 - _tNm0;
        // === numeric accumulate END ===
      }

      if (!(validTree && validNumeric && validRangeLow && validRangeHigh)) {
        isValidClaims = false;
      }
    }
  }

  // === bls_verify_ms START ===
  const _tBls0 = performance.now();
  // Verify the signature
  const isValidSignature = bls.AugSchemeMPL.verify(publicKey,
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