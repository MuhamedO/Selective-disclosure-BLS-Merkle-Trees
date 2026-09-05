import { MerkleTree}  from 'merkletreejs';
import loadBls from "bls-signatures";
import sha256 from 'crypto-js/sha256.js';
import fs  from 'fs';
import path from 'path';
import { performance } from 'perf_hooks';


async function aggregateClaimsAndSignatures(claimsFiles, rootSignatureFiles) {
  // Initialize the BLS library
  
  var bls = await loadBls();


  let aggregatedClaims = [];
  let signatures = [];

  // Process disclosed claims and proofs
  claimsFiles.forEach(filePath => {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    aggregatedClaims.push(data.revealedClaims);
  });

  // Process roots and signatures, and collect signatures for aggregation
  rootSignatureFiles.forEach(filePath => {
    const { issuer, signature } = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    signatures.push(signature);
  });

  // === total_aggregation_ms START ===
  const _tAgg0 = performance.now();

  // Convert signatures from hex to Signature objects
  signatures = signatures.map(sigHex => bls.G2Element.fromBytes(Buffer.from(sigHex, 'hex')));

  // Aggregate the signatures
  const aggregatedSignature = bls.AugSchemeMPL.aggregate(signatures);

  const _tAgg1 = performance.now();
  // === total_aggregation_ms END ===

  // Prepare the output object
  const output = {
    aggregatedClaims,
    aggregatedSignature: Buffer.from(aggregatedSignature.serialize()).toString('hex')
  };

  // Write the aggregated data to a JSON file
  const outputFilename = 'aggregatedClaimsAndSignatures.json';
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');

  console.log(`Aggregated data saved to ${outputFilename}`);

  // --- Metrics ---
  const metrics = {
    phase: 'aggregation',
    total_aggregation_ms: _tAgg1 - _tAgg0
  };

  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'aggregation_metrics.json'), JSON.stringify(metrics, null, 2), 'utf8');
  }

  // --- Size metrics ---
  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    const aggFileBytes = fs.statSync(outputFilename).size;
    const sizeMetrics = {
      phase: 'aggregation_sizes',
      aggregated_presentation_bytes: aggFileBytes
    };
    fs.writeFileSync(path.join(dir, 'aggregation_sizes_metrics.json'), JSON.stringify(sizeMetrics, null, 2), 'utf8');
  }
}

// Example usage
export default aggregateClaimsAndSignatures;