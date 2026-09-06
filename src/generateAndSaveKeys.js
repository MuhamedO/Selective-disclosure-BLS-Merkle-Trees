
import loadBls from "bls-signatures";
import fs  from 'fs';
import crypto from 'crypto';
import path from 'path';
import { performance } from 'perf_hooks';


async function generateAndSaveKeys(issuerName) {


  var bls = await loadBls();
  // === keygen_ms START ===
  const _t0 = performance.now();
  // Generate a private key
  const privateKey = bls.AugSchemeMPL.key_gen(crypto.randomBytes(32));

  // Get the public key from the private key
  const publicKey = privateKey.get_g1();
  const _t1 = performance.now();
  // === keygen_ms END ===

  // Convert keys to hexadecimal strings for storage
  const privateKeyHex = bls.Util.hex_str(privateKey.serialize());
  const publicKeyHex = bls.Util.hex_str(publicKey.serialize());

  // Prepare objects to write to JSON, including the issuer name
  const privateKeyObj = { issuer: issuerName, privateKey: privateKeyHex };
  const publicKeyObj = { issuer: issuerName, publicKey: publicKeyHex };

  // Filenames include the issuer name for uniqueness
  const privateKeyFilename = `${issuerName}_privateKey.json`;
  const publicKeyFilename = `${issuerName}_publicKey.json`;

  // Write the private key to a JSON file
  fs.writeFile(privateKeyFilename, JSON.stringify(privateKeyObj, null, 2), (err) => {
    if (err) throw err;
    console.log('Private key has been saved to ' + privateKeyFilename);
  });

  // Write the public key to a JSON file
  fs.writeFile(publicKeyFilename, JSON.stringify(publicKeyObj, null, 2), (err) => {
    if (err) throw err;
    console.log('Public key has been saved to ' + publicKeyFilename);
  });

  // --- Metrics ---
  const metrics = {
    phase: 'keygen',
    keygen_ms: _t1 - _t0
  };
  if (process.env.BENCH_OUT_DIR) {
    const dir = process.env.BENCH_OUT_DIR;
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `keygen_${issuerName}_metrics.json`), JSON.stringify(metrics, null, 2), 'utf8');
  }
}

export default generateAndSaveKeys;
