import { doTheAttack, getTheGlobalBlob, blockLen } from './padding-oracle';
import './style.css';

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
    'static-hex',
    {
      formatter: toHex,
      defaultValue: '',
      css: 'static-hex',
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
    'bruteforce',
    {
      label: 'Bruteforce block',
      type: 'hex',
      explainer:
        'The workspace of the attack. During the attack, this block is prepended to our target block.',
    },
  ],
  [
    'block',
    {
      label: 'Target block',
      type: 'static-hex',
      explainer: 'The ciphertext we are trying to crack. It never changes.',
    },
  ],
  [
    'intermediate',
    {
      label: 'Decrypted Data',
      type: 'hex',
      explainer:
        'The decrypted target block data. This still needs to be XORed with the original IV block to get plaintext.',
    },
  ],
  [
    'original-iv',
    {
      label: 'Original IV',
      type: 'static-hex',
      explainer: 'The original IV block that came with our ciphertext. It never changes.',
    },
  ],
  [
    'plaintext',
    {
      label: 'Recovered Plaintext',
      type: 'plaintext',
      explainer:
        'The result of XORing the decrypted data with the original IV block. Represented as ASCII instead of hex.',
    },
  ],
]);

const remainingFrames = [];

function createTable() {
  const tableContainer = document.getElementById('table-container');
  const tableElement = document.createElement('table');
  tableElement.setAttribute('id', 'padding-oracle-table');
  tableContainer.appendChild(tableElement);

  let rowIndex = 0;
  sections.forEach((val, sectionName) => {
    const tableRowElement = tableElement.insertRow(rowIndex);
    tableRowElement.setAttribute('id', `${sectionName}-row`);
    tableRowElement.setAttribute('class', 'demo');

    const tableRowCellSectionName = tableRowElement.insertCell(0);
    tableRowCellSectionName.setAttribute(
      'class',
      `demo ${types.get(sections.get(sectionName).type).css}`
    );
    tableRowCellSectionName.setAttribute('id', sectionName);
    tableRowCellSectionName.innerText = sections.get(sectionName).label;

    tableRowElement.onmouseover = function insertExplainer() {
      const explainerDiv = document.getElementById('explainer');
      explainerDiv.innerText = sections.get(sectionName).explainer;
    };
    tableRowElement.onmouseout = function removeExplainer() {
      const explainerDiv = document.getElementById('explainer');
      explainerDiv.innerText = '';
    };

    const defaultCellValue = types.get(sections.get(sectionName).type).defaultValue;
    for (let i = 0; i < blockLen; i += 1) {
      const tableRowCell = tableRowElement.insertCell(i + 1);
      tableRowCell.setAttribute('class', `demo ${types.get(sections.get(sectionName).type).css}`);
      tableRowCell.setAttribute('align', 'center');
      tableRowCell.setAttribute('id', `${sectionName}-${i}`);
      tableRowCell.innerText = defaultCellValue;
    }
    rowIndex += 1;
  });
}

function updateTables(updateFrame) {
  const sectionName = updateFrame.type;
  const sectionData = updateFrame.data;

  const formatterFunc = types.get(sections.get(sectionName).type).formatter;
  const formattedData = formatterFunc(sectionData);

  formattedData.forEach((val, i) => {
    const tableElement = document.getElementById(`${sectionName}-${i}`);
    tableElement.innerText = val;
  });

  const descriptionDiv = document.getElementById('description');
  descriptionDiv.innerText = `Current step: ${updateFrame.description}`;
}

async function getAnimationData() {
  await doTheAttack();
  return getTheGlobalBlob();
}

function resetAnimation() {
  sections.forEach((val, sectionName) => {
    const defaultCellValue = types.get(sections.get(sectionName).type).defaultValue;
    for (let i = 0; i < blockLen; i += 1) {
      const tableRowCell = document.getElementById(`${sectionName}-${i}`);
      tableRowCell.innerText = defaultCellValue;
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
    const animationSpeedMs = 30;

    animationData.forEach((frame, i) => {
      remainingFrames.push(
        setTimeout(() => {
          updateTables(frame);
        }, i * animationSpeedMs)
      );
    });
  });
}

function component() {
  const tableContainer = document.createElement('div');
  tableContainer.setAttribute('id', 'table-container');
  document.body.appendChild(tableContainer);

  const runButton = document.createElement('input');
  runButton.setAttribute('type', 'submit');
  runButton.setAttribute('value', 'Begin Padding Oracle Attack');
  runButton.addEventListener('click', animateOracleAttack);
  document.body.appendChild(runButton);

  const explainerDiv = document.createElement('div');
  explainerDiv.setAttribute('id', 'explainer');
  explainerDiv.innerText = 'hover on a cell for an explanation';

  const explainDiv = document.createElement('div');
  explainDiv.innerText = 'Explain: ';

  explainDiv.appendChild(explainerDiv);
  document.body.appendChild(explainDiv);

  const descriptionDiv = document.createElement('div');
  descriptionDiv.setAttribute('id', 'description');
  document.body.appendChild(descriptionDiv);

  createTable();
}

document.body.onload = component();
