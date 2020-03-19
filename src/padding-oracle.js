export const blockLen = 16;

let massiveBlob = [];
let globalIndex = 0;

async function encryptAsync(iv, secret) {
  const key = new TextEncoder('utf-8').encode('key key key keyy');
  // TODO: need to do a looooot more error handling
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'AES-CBC',
    },
    true,
    ['encrypt', 'decrypt']
  );
  const encrypted = await window.crypto.subtle.encrypt(
    {
      name: 'AES-CBC',
      iv,
    },
    cryptoKey,
    secret
  );
  return encrypted;
}

async function decryptAsync(iv, ciphertext) {
  const key = new TextEncoder('utf-8').encode('key key key keyy');
  const cryptoKey = await window.crypto.subtle.importKey(
    'raw',
    key,
    {
      name: 'AES-CBC',
    },
    true,
    ['encrypt', 'decrypt']
  );
  const decrypted = await window.crypto.subtle.decrypt(
    {
      name: 'AES-CBC',
      iv,
    },
    cryptoKey,
    ciphertext
  );
  return decrypted;
}

async function isPaddedCorrectly(iv, ciphertext) {
  const didDecrypt = await decryptAsync(iv, ciphertext).catch(() => {
    return false;
  });
  if (didDecrypt === false) {
    return false;
  }
  return true;
}

async function addEventToGlobalBlob(sectionName, data, description) {
  let wrapperData = new Uint8Array(blockLen);
  if (data.length !== blockLen) {
    data.forEach((val, i) => {
      wrapperData[blockLen - 1 - i] = data[data.length - 1 - i];
    });
  } else {
    wrapperData = data.slice();
  }

  massiveBlob[globalIndex] = {
    type: sectionName,
    data: wrapperData,
    description,
  };
  globalIndex += 1;
}

export function getTheGlobalBlob() {
  return massiveBlob;
}

async function getLastNBytes(block) {
  // 1. pick a few random words r1,..rb
  const r = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
  const rLastIdx = r.length - 1;
  const origValue = r[rLastIdx];

  /* eslint no-console: ["error", { allow: ["warn","error"] }] */
  if (r.length !== blockLen && block.length !== blockLen) {
    console.error(r.length);
    console.error(block.length);
    throw new Error('bad length');
  }

  await addEventToGlobalBlob(
    'block',
    block,
    "The ciphertext we're trying to crack the last bytes of"
  );
  await addEventToGlobalBlob('bruteforce', r, 'The initial fake IV');

  /* eslint no-bitwise: ["error", { "allow": ["^=","^"] }] */
  // 1 ...and take i=0
  for (let i = 0; i < 256; i += 1) {
    // pick r=r1,...r(b-1), (rb^i)
    r[rLastIdx] ^= i;

    await addEventToGlobalBlob('bruteforce', r, 'Guessing last byte');

    // 3. if asking the oracle about (r | y) fails, increment i and go back to the previous step
    let res = await isPaddedCorrectly(r, block);
    if (res === true) {
      // 4. replace rb by (rb ^ i)
      break;
    }
    // 4. (implied -- don't replace rb with (rb ^ i) for next iteration
    r[rLastIdx] = origValue;
  }
  await addEventToGlobalBlob('bruteforce', r, 'Found last byte');

  // 5. for n = b  down to 2, do
  // (we actually want be to be the last index)
  const b = blockLen - 1;
  for (let n = b; n >= 2; n -= 1) {
    //  a. take r=r1,...r(b-n), (r(b-n+1) ^ 1), r(b-n+2)...rb
    const nextOrigValue = r[b - n + 1];
    r[b - n + 1] ^= 1;

    // This is a special case -- we're checking to see if our randomly made
    // block happens to generate non-one padding
    await addEventToGlobalBlob('bruteforce', r, 'Checking for non-1 padding');
    //  b. if O(r|y) fails, stop and output (r(b-n+1)^n)...(rb ^ n)
    const res = await isPaddedCorrectly(r, block);
    if (res === false) {
      const answer = new Uint8Array(b - (b - n + 1));
      for (let j = b - n + 1; j <= b; j += 1) {
        answer[b - j] = r[j] ^ n;
      }
      await addEventToGlobalBlob('intermediate', answer, 'Found non-1 padding');
      return answer;
    }
    r[b - n + 1] = nextOrigValue;
  }
  // 6. output rb ^ 1
  const answer = new Uint8Array(1);
  answer[0] = r[b] ^ 1;
  await addEventToGlobalBlob('intermediate', answer, 'Found last byte');
  return answer;
}

async function recoverNextByte(known, block) {
  // Assuming we can get a(j) through a(b)
  const ajb = known;
  const ajbLen = ajb.length;

  // Last index of b
  const b = blockLen - 1;

  // Where in the 16 bytes does a(j) begin?
  const jIdx = b - ajbLen + 1;

  // 1. take r(k) = a(k) ^ (b -j + 2) for k = j...b
  const r = new Uint8Array(16);
  for (let k = jIdx; k < blockLen; k += 1) {
    r[k] = ajb[k - jIdx] ^ (b - jIdx + 2);
  }

  // 2. pick r1,....r(j-1) at random and take i=0
  for (let i = 0; i < jIdx; i += 1) {
    r[i] = 0;
  }
  await addEventToGlobalBlob('bruteforce', r, 'Created false IV for next byte recovery');

  // 2. ... and take i=0
  for (let i = 0; i < 256; i += 1) {
    // 3. take r=r1...r(j-2), (r(j-1) ^ i), rj....rb
    const origValue = r[jIdx - 1];
    r[jIdx - 1] ^= i;
    await addEventToGlobalBlob('bruteforce', r, 'Guessing next byte');

    // 4. if asking oracle about r|y returns padding error then increment i and go back to the previous step
    const isPaddedRight = await isPaddedCorrectly(r, block);
    r[jIdx - 1] = origValue;
    if (isPaddedRight === true) {
      //  5. output r(j-1) ^ i ^ (b - j + 2)
      const answer = r[jIdx - 1] ^ i ^ (b - jIdx + 2);
      return answer;
    }
  }
  throw new Error('Unable to recover byte');
}

// TODO: gross to pass in prev for the display here ;_;
async function getTheRestOfTheBlock(known, block, prev) {
  // TODO: check how Js does param passing
  const currentKnown = Array.from(known);
  for (let i = blockLen - known.length; i > 0; i -= 1) {
    let nextLetter = await recoverNextByte(new Uint8Array(currentKnown), block);
    currentKnown.unshift(nextLetter);
    await addEventToGlobalBlob('intermediate', currentKnown, 'Recovered another intermediate byte');

    const showPlaintextAlongTheWay = new Uint8Array(blockLen);
    for (let j = 0; j < currentKnown.length; j += 1) {
      showPlaintextAlongTheWay[blockLen - 1 - j] =
        currentKnown[currentKnown.length - 1 - j] ^ prev[blockLen - 1 - j];
    }
    await addEventToGlobalBlob(
      'plaintext',
      showPlaintextAlongTheWay,
      'Recovered byte of plaintext'
    );
  }

  return currentKnown;
}

// TODO: this func was separated out because it's helpful when brute forcing text
// but it makes things messier if we are only demoing decryption. figure this out
export async function decryptionOracleAttack(ciphertext) {
  if (ciphertext.length % blockLen !== 0) {
    throw new Error('wrong len');
  }
  // treat the prepended IV as a block
  const numBlocks = ciphertext.length / blockLen;
  const results = [];

  for (let blockNumber = numBlocks; blockNumber > 1; blockNumber -= 1) {
    const curBlock = ciphertext.slice((blockNumber - 1) * blockLen, blockNumber * blockLen);
    if (curBlock.length !== blockLen) {
      throw new Error('wrong block size');
    }

    const lastNBytes = await getLastNBytes(curBlock);

    // doing a little side work to make the presentation nicer
    const prevBlock = ciphertext.slice((blockNumber - 2) * blockLen, (blockNumber - 1) * blockLen);
    const showPlaintextAlongTheWay = new Uint8Array(16);

    // do this for last n bytes
    for (let i = 0; i < lastNBytes.length; i += 1) {
      showPlaintextAlongTheWay[blockLen - 1 - i] =
        lastNBytes[lastNBytes.length - 1 - i] ^ prevBlock[blockLen - 1 - i];
    }
    await addEventToGlobalBlob(
      'plaintext',
      showPlaintextAlongTheWay,
      'Recovered byte of plaintext'
    );

    const recovered = await getTheRestOfTheBlock(lastNBytes, curBlock, prevBlock);

    Array.prototype.unshift.apply(results, recovered);
  }

  return results;
}

async function xorTwoBlocks(iv, recovered) {
  await addEventToGlobalBlob('intermediate', recovered, 'Got full block of intermediate');
  if (iv.length !== recovered.length && recovered.length !== blockLen) {
    console.error(iv.length);
    console.error(recovered.length);
    throw new Error('block size mismatch');
  }

  const plaintext = [];

  for (let i = 0; i < blockLen; i += 1) {
    plaintext[i] = iv[i] ^ recovered[i];
  }

  return plaintext;
}

async function oracleAttack(ciphertext) {
  // treat the prepended IV as a block
  const numBlocks = ciphertext.length / blockLen;

  const intermediate = await decryptionOracleAttack(ciphertext);

  const plaintext = [];
  for (let blockNumber = numBlocks; blockNumber > 1; blockNumber -= 1) {
    const recovered = intermediate.slice(
      (blockNumber - 2) * blockLen,
      (blockNumber - 1) * blockLen
    );
    const prevBlock = ciphertext.slice((blockNumber - 2) * blockLen, (blockNumber - 1) * blockLen);
    if (prevBlock.length !== blockLen && recovered.length !== blockLen) {
      throw new Error('wrong block size');
    }

    const blockAnswer = await xorTwoBlocks(prevBlock, recovered);
    plaintext.unshift(...blockAnswer);
    await addEventToGlobalBlob('plaintext', plaintext, 'Plaintext recovered');
  }

  return plaintext;
}

export async function doTheAttack() {
  massiveBlob = [];
  globalIndex = 0;
  const testIV = new TextEncoder('utf-8').encode('plain normal iv!');
  const testSecrets = [
    new TextEncoder('utf-8').encode('Hack the Planet'),
    new TextEncoder('utf-8').encode('Crash Override'),
    new TextEncoder('utf-8').encode('Padding Oracle'),
    new TextEncoder('utf-8').encode('Super Mario RPG'),
  ];
  const testSecret = testSecrets[Math.floor(Math.random() * testSecrets.length)];
  const ciphertext = new Uint8Array(await encryptAsync(testIV, testSecret));
  await addEventToGlobalBlob('original-iv', testIV, 'The original input IV');
  //await addEventToGlobalBlob('ciphertext', ciphertext, 'Input Ciphertext');

  // TODO: next 2 lines are a total hackjob
  const key = new TextEncoder('utf-8').encode('key key key keyy');
  //await addEventToGlobalBlob('key', key, 'Secret key');

  const ivPlusCiphertext = new Uint8Array(testIV.length + ciphertext.length);
  ivPlusCiphertext.set(testIV);
  ivPlusCiphertext.set(ciphertext, testIV.length);

  await oracleAttack(ivPlusCiphertext);
}

// TODO: replace the below with unit tests in Jest framework
/*
// TODO: is there an easy test framework for JS to replace this with?
async function runTests() {
  let testIV = new TextEncoder('utf-8').encode('that is an iv ma');
  let testSecret = new TextEncoder('utf-8').encode('that is a cat, and that over there is a dog');

  // test encryption
  let ciphertext = new Uint8Array(await encryptAsync(testIV, testSecret));
  let knownCiphertext = [
    42,
    25,
    164,
    144,
    239,
    196,
    207,
    189,
    56,
    99,
    38,
    160,
    42,
    118,
    155,
    228,
    12,
    8,
    151,
    245,
    135,
    2,
    13,
    175,
    173,
    211,
    128,
    147,
    2,
    80,
    14,
    208,
    74,
    5,
    48,
    246,
    133,
    74,
    96,
    175,
    152,
    62,
    16,
    181,
    204,
    149,
    248,
    53,
  ];

  if (ciphertext.length != knownCiphertext.length) {
    console.error(ciphertext.length);
    console.error(knownCiphertext.length);
    return;
  }
  for (let i = 0; i < ciphertext.length; i++) {
    if (ciphertext[i] != knownCiphertext[i]) {
      console.error('arr not equal');
      return;
    }
  }

  // test decryption
  let plaintext = new Uint8Array(await decryptAsync(testIV, ciphertext));
  if (plaintext.length != testSecret.length) {
    console.error(plaintext.length);
    console.error(testSecret.length);
    return;
  }
  for (let i = 0; i < plaintext.length; i++) {
    if (plaintext[i] != testSecret[i]) {
      console.error('arr not equal');
      return;
    }
  }

  // test padded correct
  let isPaddedCorrectly1 = await isPaddedCorrectly(testIV, ciphertext);
  if (isPaddedCorrectly1 != true) {
    console.error(isPaddedCorrectly1);
    return;
  }

  // test padded incorrect
  let fakeIV = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
  let isPaddedCorrectly2 = await isPaddedCorrectly(fakeIV, ciphertext);
  if (isPaddedCorrectly2 != false) {
    console.error(isPaddedCorrectly2);
    return;
  }

  //test getLastNBytes
  let getLastCipher = new Uint8Array(await encryptAsync(testIV, testSecret));
  let lastBlock = getLastCipher.slice(getLastCipher.length - blockLen, getLastCipher.length);
  if (lastBlock.length != blockLen) {
    console.error(lastBlock.length);
    return;
  }

  let lastNBytes = await getLastNBytes(lastBlock);
  if (lastNBytes.length != 1) {
    console.error(lastNBytes.length);
    return;
  }
  if (lastNBytes[0] != 213) {
    console.error(lastNBytes[0]);
    return;
  }

  //test recoverNextByte
  let nextByte = await recoverNextByte(lastNBytes, lastBlock);
  if (nextByte != 11) {
    console.error(nextByte);
    return;
  }

  //test getTheRestOfTheBlock
  // note: dont use nextByte from above
  let restOfTheBlock = await getTheRestOfTheBlock(lastNBytes, lastBlock);
  let knownRestOfTheBlock = [
    126,
    109,
    183,
    156,
    244,
    34,
    108,
    143,
    201,
    188,
    231,
    150,
    7,
    85,
    11,
    213,
  ];
  if (restOfTheBlock.length != knownRestOfTheBlock.length) {
    console.error(restOfTheBlock.length);
    return;
  }
  for (let i = 0; i < restOfTheBlock.length; i++) {
    if (restOfTheBlock[i] != knownRestOfTheBlock[i]) {
      console.error('arr not equal');
      return;
    }
  }

  //test oracleAttack
  let ivPlusCiphertext = new Uint8Array(testIV.length + ciphertext.length);
  ivPlusCiphertext.set(testIV);
  ivPlusCiphertext.set(ciphertext, testIV.length);

  let oracle = await oracleAttack(ivPlusCiphertext);
  let knownPaddedPlaintext = 'that is a cat, and that over there is a dog' + '\x05\x05\x05\x05\x05';
  if (oracle.length != knownPaddedPlaintext.length) {
    console.error('wrong lengths');
    console.error(oracle.length);
    console.error(knownPaddedPlaintext.length);
    return;
  }

  for (let i = 0; i < oracle.length; i++) {
    if (oracle[i] != knownPaddedPlaintext.charCodeAt(i)) {
      console.error('arr not equal');
      return;
    }
  }

  // to print our successful decoding:
  // console.error(new TextDecoder("utf-8").decode(new Uint8Array(oracle)))
}
*/
