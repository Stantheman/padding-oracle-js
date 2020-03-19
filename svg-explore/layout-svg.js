function toHex(inputArr) {
  const newArr = [];
  inputArr.forEach((val, index) => {
    newArr[index] = val.toString(16).padStart(2, '0').toUpperCase();
  });
  return newArr;
}

function toAscii(inputArr) {
  const newArr = [];
  inputArr.forEach((val, index) => {
    if (val === 0) {
      newArr[index] = '';
      // TODO: do a better check for isPrintable, no hardcoded numbers
    } else if (val < 32 || val > 127) {
      // TODO: this is gross, the array wrapping/unwrapping thing
      [newArr[index]] = toHex([val]);
    } else {
      newArr[index] = String.fromCharCode(val);
    }
  });
  return newArr;
}

// TODO: make the objects instead of maps since nobody uses maps
const types = new Map([
  [
    'hex',
    {
      formatter: toHex,
      defaultValue: '00',
      css: 'hex',
    },
  ],
  [
    'plaintext',
    {
      formatter: toAscii,
      defaultValue: '',
      css: 'plaintext',
    },
  ],
]);

const sections = new Map([
  [
    'iv',
    {
      label: 'Initialization Vector (IV)',
      type: 'hex',
      prefixes: ['iv-left-'],
    },
  ],
  [
    'ciphertext',
    {
      label: 'Ciphertext data',
      type: 'hex',
      prefixes: ['ciphertext-left-', 'ciphertext-right-'],
    },
  ],
  [
    'intermediate',
    {
      label: 'Intermediate Results',
      type: 'hex',
      // I think this is actually not correct. "intermediate" is a stan term for
      // the value we use later to recover plaintext, not the actual decrypted bytes
      // TODO: come back here to flesh out more
      prefixes: ['decrypted-left-', 'decrypted-right-'],
    },
  ],
  [
    'block',
    {
      label: 'Decrypted data',
      type: 'hex',
      prefixes: ['decrypted-left-', 'decrypted-right-'],
    },
  ],
  [
    'key',
    {
      label: 'Key',
      type: 'hex',
      prefixes: ['key-left-'],
    },
  ],
  [
    'plaintext',
    {
      label: 'Recovered Plaintext',
      type: 'plaintext',
      prefixes: ['plaintext-left-', 'plaintext-right-'],
    },
  ],
]);

const remainingFrames = [];

/*
 * updateFrame looks like this:

    massiveBlob[globalIndex] = {
      type: sectionName,
      data: wrapperData,
      description,
    };

*/
function updateTables(updateFrame) {
  const sectionName = updateFrame.type;
  const sectionData = updateFrame.data;

  const formatterFunc = types.get(sections.get(sectionName).type).formatter;
  const formattedData = formatterFunc(sectionData);
  // for now, hardcode the first prefix, which is the "left" one
  const idPrefix = sections.get(sectionName).prefixes[0];

  formattedData.forEach((val, i) => {
    const tableElement = document.getElementById(`${idPrefix}${i}`);
    tableElement.textContent = val;
  });

  /*
  const descriptionDiv = document.getElementById('description');
  descriptionDiv.textContent = `Current step: ${updateFrame.description}`;
  */
}

async function getAnimationData() {
  await window.doTheAttack();
  return window.getTheGlobalBlob();
}

function resetAnimation() {
  sections.forEach((val, sectionName) => {
    const defaultCellValue = types.get(sections.get(sectionName).type).defaultValue;
    const idPrefix = sections.get(sectionName).prefixes[0];
    for (let i = 0; i < window.blockLen; i += 1) {
      const tableRowCell = document.getElementById(`${idPrefix}${i}`);
      tableRowCell.textContent = defaultCellValue;
    }
  });
  remainingFrames.forEach((val) => {
    clearTimeout(val);
  });
  remainingFrames.length = 0;
}

function animateOracleAttack() {
  resetAnimation();
  getAnimationData().then((animationData) => {
    const animationSpeedMs = 50;

    animationData.forEach((frame, i) => {
      remainingFrames.push(
        setTimeout(() => {
          updateTables(frame);
        }, i * animationSpeedMs)
      );
    });
  });
}

window.animateOracleAttack = animateOracleAttack;
