import { buildPoseidon } from 'circomlibjs';

const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

let poseidonInstance = null;
let field = null;

async function initPoseidon() {
  if (!poseidonInstance) {
    poseidonInstance = await buildPoseidon();
    field = poseidonInstance.F;
  }
  return { poseidon: poseidonInstance, F: field };
}

function strip0x(hex) {
  return hex.startsWith('0x') ? hex.slice(2) : hex;
}

function hexToField(hex) {
  const clean = strip0x(hex);
  if (!clean) return 0n;
  return BigInt('0x' + clean) % FIELD_PRIME;
}

function normalizeHex32(hex) {
  return strip0x(hex).padStart(64, '0');
}

async function poseidonToHex(inputs) {
  const { poseidon, F } = await initPoseidon();
  const result = poseidon(inputs);
  return normalizeHex32(F.toObject(result).toString(16));
}

export async function hashLeaf(leafHex) {
  return poseidonToHex([hexToField(leafHex)]);
}

export async function hashPair(leftHex, rightHex) {
  let left = hexToField(leftHex);
  let right = hexToField(rightHex);

  // same idea as sortPairs: true
  if (left > right) {
    [left, right] = [right, left];
  }

  return poseidonToHex([left, right]);
}

export async function buildPoseidonTree(rawLeaves) {
  if (!rawLeaves.length) {
    throw new Error('Cannot build tree with no leaves');
  }

  let currentLevel = await Promise.all(rawLeaves.map(hashLeaf));
  const levels = [currentLevel];

  while (currentLevel.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : currentLevel[i];
      nextLevel.push(await hashPair(left, right));
    }

    levels.push(nextLevel);
    currentLevel = nextLevel;
  }

  return {
    levels,
    root: levels[levels.length - 1][0]
  };
}

export function getProof(tree, leafIndex) {
  const proof = [];
  let index = leafIndex;

  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level];
    const isRightNode = index % 2 === 1;

    let siblingIndex;
    if (isRightNode) {
      siblingIndex = index - 1;
      proof.push({ position: 'left', data: nodes[siblingIndex] });
    } else {
      siblingIndex = index + 1 < nodes.length ? index + 1 : index;
      proof.push({ position: 'right', data: nodes[siblingIndex] });
    }

    index = Math.floor(index / 2);
  }

  return proof;
}

export async function verifyProof(rawLeafHex, proof, expectedRootHex) {
  let current = await hashLeaf(rawLeafHex);

  for (const step of proof) {
    if (step.position === 'left') {
      current = await hashPair(step.data, current);
    } else {
      current = await hashPair(current, step.data);
    }
  }

  return normalizeHex32(current) === normalizeHex32(expectedRootHex);
}
