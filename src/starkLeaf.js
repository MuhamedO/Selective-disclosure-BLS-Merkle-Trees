import fs from 'fs';
import path from 'path';
import { stringToBigInt } from './utils.js';

export function claimValueToBigInt(value) {
  if (typeof value === 'string') {
    return stringToBigInt(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`Invalid numeric value: ${value}`);
    }
    return BigInt(Math.round(value));
  }
  return BigInt(value);
}

export function normalizeHex32FromBigInt(value) {
  return value.toString(16).padStart(64, '0');
}

export function loadClaimTags() {
  const claimTagsPath = path.resolve(process.cwd(), 'claimTags.json');
  if (!fs.existsSync(claimTagsPath)) {
    throw new Error(`claimTags.json not found at ${claimTagsPath}`);
  }
  return JSON.parse(fs.readFileSync(claimTagsPath, 'utf8'));
}

export function hasClaimTag(claimKey, claimTags) {
  return Object.prototype.hasOwnProperty.call(claimTags, claimKey);
}

export function getClaimMeta(claimKey, claimTags) {
  if (!hasClaimTag(claimKey, claimTags)) {
    throw new Error(`Missing claim metadata for numeric claim "${claimKey}"`);
  }

  const meta = claimTags[claimKey];
  if (typeof meta === 'number') {
    return { claim_tag: meta, scale: 1 };
  }

  return {
    claim_tag: meta.claim_tag,
    scale: meta.scale ?? 1,
  };
}

export function isStarkNumericClaim(claimKey, claimValue, claimTags) {
  return hasClaimTag(claimKey, claimTags) && typeof claimValue === 'number';
}

export function encodeNumericClaimValue(value, scale = 1) {
  if (typeof value !== 'number') {
    throw new Error(`Expected numeric claim value, got ${typeof value}`);
  }
  if (!Number.isFinite(value)) {
    throw new Error(`Invalid numeric claim value: ${value}`);
  }
  return BigInt(Math.round(value * scale));
}

export function encodeBound(bound, scale = 1) {
  if (typeof bound !== 'number') {
    bound = Number(bound);
  }
  if (!Number.isFinite(bound)) {
    throw new Error(`Invalid numeric bound: ${bound}`);
  }
  return BigInt(Math.round(bound * scale));
}

export function computeLeafDigestBigIntFromEncoded(encodedValue, claimTag, blinding) {
  const v = BigInt(encodedValue);
  const tag = BigInt(claimTag);
  const blind = BigInt(blinding);
  return v * v * v + 7n * v + 11n + 131n * tag + blind;
}

export function computeLeafDigestHexFromEncoded(encodedValue, claimTag, blinding) {
  return normalizeHex32FromBigInt(
    computeLeafDigestBigIntFromEncoded(encodedValue, claimTag, blinding)
  );
}

export function computeLeafDigestHex(value, claimTag, blinding, scale = 1) {
  const encoded = encodeNumericClaimValue(value, scale);
  return computeLeafDigestHexFromEncoded(encoded, claimTag, blinding);
}