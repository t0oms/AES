// made by - Toms Pētersons, tp22016

// 1. AES BLOCK CYPHER

const SBOX = [
  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
  [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
  [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
  [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
  [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
  [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
  [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
  [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
  [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
  [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
  [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
  [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
  [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
  [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
  [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
  [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16],
];


const INV_SBOX = [
  [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
  [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
  [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
  [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
  [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
  [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
  [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
  [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
  [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
  [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
  [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
  [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
  [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
  [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
  [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
  [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
];


// round constants
const RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


function stringToBytes(str) {
  // convert hexadecimal string to an array of bytes

  let bytes = [];

  for (let i = 0; i < str.length; i+=2) {
    bytes.push(parseInt(str.substr(i, 2), 16));
  }

  return new Uint8Array(bytes); 
}


function xorWord(wordA, wordB) {
  const result = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    result[i] = wordA[i] ^ wordB[i];
  }
  return result;
}


function gFunc(word, round) {
  const result = new Uint8Array(4);

  // rotate words 
  result[0] = word[1];
  result[1] = word[2];
  result[2] = word[3];
  result[3] = word[0];

  // apply s-box to each byte
  for (let i = 0; i < 4; i++) {
    // first part of byte is row
    const row = result[i] >> 4;
    // second part is col
    const col = result[i] & 0x0f;

    result[i] = SBOX[row][col];
  }

  // xor with round constant
  result[0] ^= RCON[round];

  return result;
}


function generateRoundKeys(key) {
  const roundKeys = [];

  // split key into 4 words
  let w0 = Uint8Array.from(key.slice(0, 4));
  let w1 = Uint8Array.from(key.slice(4, 8));
  let w2 = Uint8Array.from(key.slice(8, 12));
  let w3 = Uint8Array.from(key.slice(12, 16));

  // first round key is the original key
  roundKeys.push([w0, w1, w2, w3]);

  // genereate 10 more round keys from the previous keys
  for (let round = 1; round <= 10; round++) {
    w0 = xorWord(w0, gFunc(w3, round));
    w1 = xorWord(w1, w0);
    w2 = xorWord(w2, w1);
    w3 = xorWord(w3, w2);

    roundKeys.push([w0, w1, w2, w3]);
  }

  return roundKeys;
}


function addRoundKey(block, roundKey) {
  // apply the round key on block (xor

  for (let i = 0; i < 16; i++) {
    block[i] ^= roundKey[Math.floor(i / 4)][i % 4];
  }
}


function subBytes(block, inverse = false) {
  // substitue byest with s-box byets, or inverse s-box bytes
  for (let i = 0; i < 16; i++) {
    const row = block[i] >> 4;
    const col = block[i] & 0x0f;

    if (!inverse) {
      block[i] = SBOX[row][col];
    } else {
      block[i] = INV_SBOX[row][col];
    }
  }
}


function shiftRows(block, inverse = false) {
  const temp = new Uint8Array(16);

  // shift the rows according to the pattern specified in the algorithm

  if (!inverse) {
    temp[0] = block[0];
    temp[1] = block[5];
    temp[2] = block[10];
    temp[3] = block[15];

    temp[4] = block[4];
    temp[5] = block[9];
    temp[6] = block[14];
    temp[7] = block[3];

    temp[8] = block[8];
    temp[9] = block[13];
    temp[10] = block[2];
    temp[11] = block[7];

    temp[12] = block[12];
    temp[13] = block[1];
    temp[14] = block[6];
    temp[15] = block[11];
  } else {
    temp[0] = block[0];
    temp[1] = block[13];
    temp[2] = block[10];
    temp[3] = block[7];

    temp[4] = block[4];
    temp[5] = block[1];
    temp[6] = block[14];
    temp[7] = block[11];

    temp[8] = block[8];
    temp[9] = block[5];
    temp[10] = block[2];
    temp[11] = block[15];

    temp[12] = block[12];
    temp[13] = block[9];
    temp[14] = block[6];
    temp[15] = block[3];
  }
  
  block.set(temp);
}


function xtime(byte) {
  // check the leftmost bit. If this bit is 1, shifting left will push it off the edge
  if ((byte & 0x80) !== 0) {

    // shift left by 1
    byte = (byte << 1);

    // xor with 0x1b (0001 1011), becaue we lost the top bit, to bring the number back into valid range
    byte = byte ^ 0x1b;
  } else {

    byte = (byte << 1);
  }

  // make sure the result stays as an 8-bit byte.
  return byte & 0xff;
}


function mixColumns(block) {
  // loop through the 4 columns 
  for (let col = 0; col < 4; col++) {
    const i = col * 4;

    // use the 4 bytes in the column
    const a0 = block[i + 0];
    const a1 = block[i + 1];
    const a2 = block[i + 2];
    const a3 = block[i + 3];

    // apply mixing forumula for each row

    // 2*a0 + 3*a1 + a2 + a3
    block[i + 0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;

    // a0 + 2*a1 + 3*a2 + a3
    block[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;

    // a0 + a1 + 2*a2 + 3*a3
    block[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);

    // 3*a0 + a1 + a2 + 2*a3
    block[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);


    // "plus" (+) becomes xor (^)
    // "times 2" becomes `xtime(val)`
    // "times 3" becomes `xtime(val) ^ val` (because 3x = 2x + 1x)
  }
}


function mul(val, type) {

  const x = xtime(val);
  const x2 = xtime(x);
  const x3 = xtime(x2);
  
  if (type === 0x09) {
    // {09} = {00001001} = x^3 + 1
    return x3 ^ val;
  }
  if (type === 0x0b) {
    // {0b} = {00001011} = x^3 + x + 1
    return x3 ^ x ^ val;
  }
  if (type === 0x0d) {
    // {0d} = {00001101} = x^3 + x^2 + 1
    return x3 ^ x2 ^ val;
  }
  if (type === 0x0e) {
    // {0e} = {00001110} = x^3 + x^2 + x
    return x3 ^ x2 ^ x;
  }

  return 0;
}


function invMixColumns(block) {

  // loop through the 4 columns 
  for (let col = 0; col < 4; col++) {
    const i = col * 4;

    // save original values
    const b0 = block[i + 0];
    const b1 = block[i + 1];
    const b2 = block[i + 2];
    const b3 = block[i + 3];

    // apply inverse matrix multipilication

    // 0e*b0 + 0b*b1 + 0d*b2 + 09*b3
    block[i + 0] = mul(b0, 0x0e) ^ mul(b1, 0x0b) ^ mul(b2, 0x0d) ^ mul(b3, 0x09);

    // 09*b0 + 0e*b1 + 0b*b2 + 0d*b3
    block[i + 1] = mul(b0, 0x09) ^ mul(b1, 0x0e) ^ mul(b2, 0x0b) ^ mul(b3, 0x0d);

    // 0d*b0 + 09*b1 + 0e*b2 + 0b*b3
    block[i + 2] = mul(b0, 0x0d) ^ mul(b1, 0x09) ^ mul(b2, 0x0e) ^ mul(b3, 0x0b);

    // 0b*b0 + 0d*b1 + 09*b2 + 0e*b3
    block[i + 3] = mul(b0, 0x0b) ^ mul(b1, 0x0d) ^ mul(b2, 0x09) ^ mul(b3, 0x0e);
  }
}

function encryptBlock(input, roundKeys) {
  const block = new Uint8Array(input);

  // apply initial round key
  addRoundKey(block, roundKeys[0]);

  // rounds 1 to 9
  for (let round = 1; round <= 9; round++) {
    subBytes(block);
    shiftRows(block);
    mixColumns(block);
    addRoundKey(block, roundKeys[round]);
  }

  // round 10
  subBytes(block);
  shiftRows(block);
  addRoundKey(block, roundKeys[10]);

  return block;
}


function decryptBlock(input, roundKeys) {
  const block = new Uint8Array(input);

  // initial round with last key
  addRoundKey(block, roundKeys[10]);

  // rounds 9 to 1 
  for (let round = 9; round >= 1; round--) {
    shiftRows(block, true);
    subBytes(block, true);
    addRoundKey(block, roundKeys[round]);
    invMixColumns(block);
  }

  // final round
  shiftRows(block, true);
  subBytes(block, true);
  addRoundKey(block, roundKeys[0]);

  return block;
}


function runBlockCipher() {
  const action = document.querySelector(
    'input[name="task1Action"]:checked'
  ).value;

  const keyStr = document.getElementById("blockKey").value;
  const inputStr = document.getElementById("blockInput").value;

  // convert from strings to byte arrays
  const key = stringToBytes(keyStr);
  const input = stringToBytes(inputStr);

  const roundKeys = generateRoundKeys(key);

  let output;

  if (action === 'encrypt') {
    output = encryptBlock(input, roundKeys);
  } else {
    output = decryptBlock(input, roundKeys);
  }

  // convert result to string
  let result = "";
  for (let i = 0; i < output.length; i++) {
    const byte = output[i];
    
    let hex = byte.toString(16);

    if (hex.length === 1) {
      hex = "0" + hex;
    }

    result += hex;
  }

  document.getElementById("blockOutput").value = result;
}


window.runBlockCipher = runBlockCipher;





// 2. FILE CYPHER

function xorBlock(blockA, blockB) {
  const result = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    result[i] = blockA[i] ^ blockB[i];
  }
  return result;
}


function padData(data) {
  // if no padding needed, still add block, to handle case where 0x01 is at the end of the data.
  const paddingByteCount = 16 - (data.length % 16);

  // create an array the size of the missing bytes and fill it with the value of paddingByteCount
  const paddingBytes = new Uint8Array(paddingByteCount).fill(paddingByteCount);

  const result = new Uint8Array(data.length + paddingByteCount);
  result.set(data);
  
  // add the padding bytes to the end 
  result.set(paddingBytes, data.length);
  return result;
}


function unpadData(data) {
  // read the last byte, which tells us how many bytes to remove
  const paddingByteCount = data[data.length - 1];

  // remove the padding bytes
  return data.slice(0, data.length - paddingByteCount);
}


function downloadFile(dataBytes, fileName) {
  // put the data into a Binary Large Object, to be able to download it
  const fileBlob = new Blob([dataBytes], { type: "application/octet-stream" });

  // create a URL from which to download
  const url = URL.createObjectURL(fileBlob);

  // add an invisible download link element to the page
  const downloadLink = document.createElement("a");
  downloadLink.href = url;
  downloadLink.download = fileName;
  document.body.appendChild(downloadLink);

  // automatically click on that linke to download
  downloadLink.click();

  // remove the link
  document.body.removeChild(downloadLink);
  URL.revokeObjectURL(url);
}


function encryptFile(fileBytes, key, initializationVector) {
  const roundKeys = generateRoundKeys(key);
  
  // pad the file data
  const paddedData = padData(fileBytes);
  const blockCount = paddedData.length / 16;
  
  // write the initializationVector at the beginning of the output file
  const outputData = new Uint8Array(16 + paddedData.length);
  outputData.set(initializationVector);
  
  let previousBlock = initializationVector; 

  // CBC Encryption Loop
  for (let i = 0; i < blockCount; i++) {
    const start = i * 16;
    const end = start + 16;
    const block = paddedData.slice(start, end);

    // apply pervious block on current block (with xor) and encrypt
    const xoredBlock = xorBlock(block, previousBlock);
    const encryptedBlock = encryptBlock(xoredBlock, roundKeys);

    // write the encrypted block
    outputData.set(encryptedBlock, 16 + start);
    
    previousBlock = encryptedBlock;
  }
  
  return outputData;
}


function decryptFile(fileBytes, key) {

  // check if the file is valid
  if (fileBytes.length < 16 || fileBytes.length % 16 !== 0) {
    throw new Error("Nepareizs fails.");
  }

  const roundKeys = generateRoundKeys(key);

  // get the initializationVector fro mthe beginning of the file 
  const initializationVector = fileBytes.slice(0, 16);
  const encryptedFileBytes = fileBytes.slice(16);
  
  const blockCount = encryptedFileBytes.length / 16;
  const outputData = new Uint8Array(encryptedFileBytes.length);
  
  let previousBlock = initializationVector; 

  // CBC Decryption Loop
  for (let i = 0; i < blockCount; i++) {
    const start = i * 16;
    const end = start + 16;
    const encryptedBlock = encryptedFileBytes.slice(start, end);

    // decrypt block and apply previous block (xor)
    const decryptedBlock = decryptBlock(encryptedBlock, roundKeys);
    const block = xorBlock(decryptedBlock, previousBlock);

    // write the block
    outputData.set(block, start);
    
    previousBlock = encryptedBlock;
  }

  // remove padding
  return unpadData(outputData);
}


async function runFileCipher() {
  const action = document.querySelector('input[name="task2Action"]:checked').value;
  const keyStr = document.getElementById("fileKey").value;
  const initializationVectorStr = document.getElementById("fileIV").value;
  const fileInput = document.getElementById("fileInput");

  // return if no file selected
  if (!fileInput.files.length) {
    return;
  }

  try {
    // convert from strings to byte arrays
    const key = stringToBytes(keyStr);
    const initializationVector = stringToBytes(initializationVectorStr);
    
    // read the file into memory and pause execution until the file is fully read
    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();
    const fileBytes = new Uint8Array(arrayBuffer);

    let resultBytes;
    let downloadName;

    if (action === 'encrypt') {
      resultBytes = encryptFile(fileBytes, key, initializationVector);

      // add .encrypted to the end of an ecrypted file
      downloadName = file.name + ".encrypted";
    } else {
      resultBytes = decryptFile(fileBytes, key);

      if (file.name.endsWith(".encrypted")) {
        // remove .encrypted from the end of a decrypted file
        downloadName = file.name.replace(".encrypted", "");
      } else {
        // in case you want to decrypte files that were not encrypted with this program
        // add decrypted_ to the start of the file to distinguish from input file
        downloadName = "decrypted_" + file.name;
      }
    }

    downloadFile(resultBytes, downloadName);

  } catch (error) {
    alert("Kļūda: " + error.message);
    console.error(error);
  }
}


window.runFileCipher = runFileCipher;