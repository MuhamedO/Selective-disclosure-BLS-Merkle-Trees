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

  // Each claim becomes { value, ...its own secret randomness }:
  //  - STARK numeric claims: blinding + encoding metadata (for the polynomial leaf digest)
  //  - all other claims: an individual Pedersen salt
  const claims = {};
  const leaves = Object.entries(claimsData).map(([key, value]) => {
    if (isStarkNumericClaim(key, value, claimTags)) {
      const meta = getClaimMeta(key, claimTags);
      const blinding = randomBlinding();
      const encodedValue = encodeNumericClaimValue(value, meta.scale);

      claims[key] = {
        value,
        blinding: blinding.toString(),
        encodedValue: encodedValue.toString(),
        claimTag: meta.claim_tag,
        scale: meta.scale,
      };

      return computeLeafDigestHexFromEncoded(encodedValue, meta.claim_tag, blinding);
    }

    const salt = Rand.randUnder(pedGenParams.n);
    claims[key] = { value, salt: salt.toString() };

    const normalizedValue = typeof value === 'string'
      ? stringToBigInt(value)
      : BigInt(Math.round(value));

    return PointFn.toHexString(
      CommitmentUtils.getPedersenCommitment(normalizedValue, salt, pedGenParams)
    );
  });

  // Create the Merkle tree
  const tree = await buildPoseidonTree(leaves);

  // Get the Merkle root
  const root = tree.root;

  // Read private key JSON file
  const privateKeyData = JSON.parse(fs.readFileSync(privateKeyJsonFilePath, 'utf8'));
  const privateKeyHex = privateKeyData.privateKey;

  // Convert the private key back to a BLS PrivateKey object
  const privateKey = bls.PrivateKey.fromBytes(Buffer.from(privateKeyHex, 'hex'), false);

  const signature = bls.AugSchemeMPL.sign(privateKey, root);
  // Sign the root with the private key
  //const signature = privateKey.sign(Buffer.from(root, 'hex'));

  // Convert the signature to hexadecimal for storage
  const signatureHex = bls.Util.hex_str(signature.serialize());

  // Prepare the output JSON object
  const output = {
    issuer: privateKeyData.issuer,
    merkleRoot: root,
    signature: signatureHex
  };

  const output2 = {
    claims,
    issuer: privateKeyData.issuer,
  };


  // Write the output to a JSON file
  const outputFilename = `${privateKeyData.issuer.replace(/[^a-z0-9]/gi, '_')}_${path.parse(claimsJsonFilePath).name}_signature.json`;
  fs.writeFileSync(outputFilename, JSON.stringify(output, null, 2), 'utf8');
  
  const outputFilename2 = `${privateKeyData.issuer.replace(/[^a-z0-9]/gi, '_')}_${path.parse(claimsJsonFilePath).name}_issued_credential.json`;
  fs.writeFileSync(outputFilename2, JSON.stringify(output2, null, 2), 'utf8');

  console.log(`Merkle root signed. Output saved to ${outputFilename}. Credential saved to ${outputFilename2}`);
}

export default createAndSignCredential;