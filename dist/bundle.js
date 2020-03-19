/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./src/layout.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./node_modules/css-loader/dist/cjs.js!./src/style.css":
/*!*************************************************************!*\
  !*** ./node_modules/css-loader/dist/cjs.js!./src/style.css ***!
  \*************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

eval("// Imports\nvar ___CSS_LOADER_API_IMPORT___ = __webpack_require__(/*! ../node_modules/css-loader/dist/runtime/api.js */ \"./node_modules/css-loader/dist/runtime/api.js\");\nexports = ___CSS_LOADER_API_IMPORT___(false);\n// Module\nexports.push([module.i, \".demo {\\n    border: 2px solid black;\\n    border-radius: 5px;\\n    width: 40px;\\n    height: 40px;\\n    justify-content: center;\\n    font-family: 'Rajdhani', sans-serif;\\n    font-size: 1.5rem;\\n}\\n.plaintext {\\n    font-weight: bold;\\n    background-color: #e6ffff;\\n}\\n.hex {\\n    background-color: #e6ffff;\\n}\\n.static-hex {\\n    background-color: #E9EFFF;\\n}\\n#explainer {\\n    display: inline-block;\\n}\\n\", \"\"]);\n// Exports\nmodule.exports = exports;\n\n\n//# sourceURL=webpack:///./src/style.css?./node_modules/css-loader/dist/cjs.js");

/***/ }),

/***/ "./node_modules/css-loader/dist/runtime/api.js":
/*!*****************************************************!*\
  !*** ./node_modules/css-loader/dist/runtime/api.js ***!
  \*****************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
eval("\n\n/*\n  MIT License http://www.opensource.org/licenses/mit-license.php\n  Author Tobias Koppers @sokra\n*/\n// css base code, injected by the css-loader\n// eslint-disable-next-line func-names\nmodule.exports = function (useSourceMap) {\n  var list = []; // return the list of modules as css string\n\n  list.toString = function toString() {\n    return this.map(function (item) {\n      var content = cssWithMappingToString(item, useSourceMap);\n\n      if (item[2]) {\n        return \"@media \".concat(item[2], \" {\").concat(content, \"}\");\n      }\n\n      return content;\n    }).join('');\n  }; // import a list of modules into the list\n  // eslint-disable-next-line func-names\n\n\n  list.i = function (modules, mediaQuery, dedupe) {\n    if (typeof modules === 'string') {\n      // eslint-disable-next-line no-param-reassign\n      modules = [[null, modules, '']];\n    }\n\n    var alreadyImportedModules = {};\n\n    if (dedupe) {\n      for (var i = 0; i < this.length; i++) {\n        // eslint-disable-next-line prefer-destructuring\n        var id = this[i][0];\n\n        if (id != null) {\n          alreadyImportedModules[id] = true;\n        }\n      }\n    }\n\n    for (var _i = 0; _i < modules.length; _i++) {\n      var item = [].concat(modules[_i]);\n\n      if (dedupe && alreadyImportedModules[item[0]]) {\n        // eslint-disable-next-line no-continue\n        continue;\n      }\n\n      if (mediaQuery) {\n        if (!item[2]) {\n          item[2] = mediaQuery;\n        } else {\n          item[2] = \"\".concat(mediaQuery, \" and \").concat(item[2]);\n        }\n      }\n\n      list.push(item);\n    }\n  };\n\n  return list;\n};\n\nfunction cssWithMappingToString(item, useSourceMap) {\n  var content = item[1] || ''; // eslint-disable-next-line prefer-destructuring\n\n  var cssMapping = item[3];\n\n  if (!cssMapping) {\n    return content;\n  }\n\n  if (useSourceMap && typeof btoa === 'function') {\n    var sourceMapping = toComment(cssMapping);\n    var sourceURLs = cssMapping.sources.map(function (source) {\n      return \"/*# sourceURL=\".concat(cssMapping.sourceRoot || '').concat(source, \" */\");\n    });\n    return [content].concat(sourceURLs).concat([sourceMapping]).join('\\n');\n  }\n\n  return [content].join('\\n');\n} // Adapted from convert-source-map (MIT)\n\n\nfunction toComment(sourceMap) {\n  // eslint-disable-next-line no-undef\n  var base64 = btoa(unescape(encodeURIComponent(JSON.stringify(sourceMap))));\n  var data = \"sourceMappingURL=data:application/json;charset=utf-8;base64,\".concat(base64);\n  return \"/*# \".concat(data, \" */\");\n}\n\n//# sourceURL=webpack:///./node_modules/css-loader/dist/runtime/api.js?");

/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js":
/*!****************************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js ***!
  \****************************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
eval("\n\nvar isOldIE = function isOldIE() {\n  var memo;\n  return function memorize() {\n    if (typeof memo === 'undefined') {\n      // Test for IE <= 9 as proposed by Browserhacks\n      // @see http://browserhacks.com/#hack-e71d8692f65334173fee715c222cb805\n      // Tests for existence of standard globals is to allow style-loader\n      // to operate correctly into non-standard environments\n      // @see https://github.com/webpack-contrib/style-loader/issues/177\n      memo = Boolean(window && document && document.all && !window.atob);\n    }\n\n    return memo;\n  };\n}();\n\nvar getTarget = function getTarget() {\n  var memo = {};\n  return function memorize(target) {\n    if (typeof memo[target] === 'undefined') {\n      var styleTarget = document.querySelector(target); // Special case to return head of iframe instead of iframe itself\n\n      if (window.HTMLIFrameElement && styleTarget instanceof window.HTMLIFrameElement) {\n        try {\n          // This will throw an exception if access to iframe is blocked\n          // due to cross-origin restrictions\n          styleTarget = styleTarget.contentDocument.head;\n        } catch (e) {\n          // istanbul ignore next\n          styleTarget = null;\n        }\n      }\n\n      memo[target] = styleTarget;\n    }\n\n    return memo[target];\n  };\n}();\n\nvar stylesInDom = [];\n\nfunction getIndexByIdentifier(identifier) {\n  var result = -1;\n\n  for (var i = 0; i < stylesInDom.length; i++) {\n    if (stylesInDom[i].identifier === identifier) {\n      result = i;\n      break;\n    }\n  }\n\n  return result;\n}\n\nfunction modulesToDom(list, options) {\n  var idCountMap = {};\n  var identifiers = [];\n\n  for (var i = 0; i < list.length; i++) {\n    var item = list[i];\n    var id = options.base ? item[0] + options.base : item[0];\n    var count = idCountMap[id] || 0;\n    var identifier = \"\".concat(id, \" \").concat(count);\n    idCountMap[id] = count + 1;\n    var index = getIndexByIdentifier(identifier);\n    var obj = {\n      css: item[1],\n      media: item[2],\n      sourceMap: item[3]\n    };\n\n    if (index !== -1) {\n      stylesInDom[index].references++;\n      stylesInDom[index].updater(obj);\n    } else {\n      stylesInDom.push({\n        identifier: identifier,\n        updater: addStyle(obj, options),\n        references: 1\n      });\n    }\n\n    identifiers.push(identifier);\n  }\n\n  return identifiers;\n}\n\nfunction insertStyleElement(options) {\n  var style = document.createElement('style');\n  var attributes = options.attributes || {};\n\n  if (typeof attributes.nonce === 'undefined') {\n    var nonce =  true ? __webpack_require__.nc : undefined;\n\n    if (nonce) {\n      attributes.nonce = nonce;\n    }\n  }\n\n  Object.keys(attributes).forEach(function (key) {\n    style.setAttribute(key, attributes[key]);\n  });\n\n  if (typeof options.insert === 'function') {\n    options.insert(style);\n  } else {\n    var target = getTarget(options.insert || 'head');\n\n    if (!target) {\n      throw new Error(\"Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid.\");\n    }\n\n    target.appendChild(style);\n  }\n\n  return style;\n}\n\nfunction removeStyleElement(style) {\n  // istanbul ignore if\n  if (style.parentNode === null) {\n    return false;\n  }\n\n  style.parentNode.removeChild(style);\n}\n/* istanbul ignore next  */\n\n\nvar replaceText = function replaceText() {\n  var textStore = [];\n  return function replace(index, replacement) {\n    textStore[index] = replacement;\n    return textStore.filter(Boolean).join('\\n');\n  };\n}();\n\nfunction applyToSingletonTag(style, index, remove, obj) {\n  var css = remove ? '' : obj.media ? \"@media \".concat(obj.media, \" {\").concat(obj.css, \"}\") : obj.css; // For old IE\n\n  /* istanbul ignore if  */\n\n  if (style.styleSheet) {\n    style.styleSheet.cssText = replaceText(index, css);\n  } else {\n    var cssNode = document.createTextNode(css);\n    var childNodes = style.childNodes;\n\n    if (childNodes[index]) {\n      style.removeChild(childNodes[index]);\n    }\n\n    if (childNodes.length) {\n      style.insertBefore(cssNode, childNodes[index]);\n    } else {\n      style.appendChild(cssNode);\n    }\n  }\n}\n\nfunction applyToTag(style, options, obj) {\n  var css = obj.css;\n  var media = obj.media;\n  var sourceMap = obj.sourceMap;\n\n  if (media) {\n    style.setAttribute('media', media);\n  } else {\n    style.removeAttribute('media');\n  }\n\n  if (sourceMap && btoa) {\n    css += \"\\n/*# sourceMappingURL=data:application/json;base64,\".concat(btoa(unescape(encodeURIComponent(JSON.stringify(sourceMap)))), \" */\");\n  } // For old IE\n\n  /* istanbul ignore if  */\n\n\n  if (style.styleSheet) {\n    style.styleSheet.cssText = css;\n  } else {\n    while (style.firstChild) {\n      style.removeChild(style.firstChild);\n    }\n\n    style.appendChild(document.createTextNode(css));\n  }\n}\n\nvar singleton = null;\nvar singletonCounter = 0;\n\nfunction addStyle(obj, options) {\n  var style;\n  var update;\n  var remove;\n\n  if (options.singleton) {\n    var styleIndex = singletonCounter++;\n    style = singleton || (singleton = insertStyleElement(options));\n    update = applyToSingletonTag.bind(null, style, styleIndex, false);\n    remove = applyToSingletonTag.bind(null, style, styleIndex, true);\n  } else {\n    style = insertStyleElement(options);\n    update = applyToTag.bind(null, style, options);\n\n    remove = function remove() {\n      removeStyleElement(style);\n    };\n  }\n\n  update(obj);\n  return function updateStyle(newObj) {\n    if (newObj) {\n      if (newObj.css === obj.css && newObj.media === obj.media && newObj.sourceMap === obj.sourceMap) {\n        return;\n      }\n\n      update(obj = newObj);\n    } else {\n      remove();\n    }\n  };\n}\n\nmodule.exports = function (list, options) {\n  options = options || {}; // Force single-tag solution on IE6-9, which has a hard limit on the # of <style>\n  // tags it will allow on a page\n\n  if (!options.singleton && typeof options.singleton !== 'boolean') {\n    options.singleton = isOldIE();\n  }\n\n  list = list || [];\n  var lastIdentifiers = modulesToDom(list, options);\n  return function update(newList) {\n    newList = newList || [];\n\n    if (Object.prototype.toString.call(newList) !== '[object Array]') {\n      return;\n    }\n\n    for (var i = 0; i < lastIdentifiers.length; i++) {\n      var identifier = lastIdentifiers[i];\n      var index = getIndexByIdentifier(identifier);\n      stylesInDom[index].references--;\n    }\n\n    var newLastIdentifiers = modulesToDom(newList, options);\n\n    for (var _i = 0; _i < lastIdentifiers.length; _i++) {\n      var _identifier = lastIdentifiers[_i];\n\n      var _index = getIndexByIdentifier(_identifier);\n\n      if (stylesInDom[_index].references === 0) {\n        stylesInDom[_index].updater();\n\n        stylesInDom.splice(_index, 1);\n      }\n    }\n\n    lastIdentifiers = newLastIdentifiers;\n  };\n};\n\n//# sourceURL=webpack:///./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js?");

/***/ }),

/***/ "./src/layout.js":
/*!***********************!*\
  !*** ./src/layout.js ***!
  \***********************/
/*! no exports provided */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
eval("__webpack_require__.r(__webpack_exports__);\n/* harmony import */ var _padding_oracle__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./padding-oracle */ \"./src/padding-oracle.js\");\n/* harmony import */ var _style_css__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./style.css */ \"./src/style.css\");\n/* harmony import */ var _style_css__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_style_css__WEBPACK_IMPORTED_MODULE_1__);\n\n\n\nfunction toHex(inputArr) {\n  const newArr = [];\n  inputArr.forEach((val, index) => {\n    newArr[index] = val.toString(16).padStart(2, '0').toUpperCase();\n  });\n  return newArr;\n}\n\nfunction toAscii(inputArr) {\n  const newArr = [];\n  inputArr.forEach((val, index) => {\n    if (val === 0) {\n      newArr[index] = '';\n      // TODO: do a better check for isPrintable, no hardcoded numbers\n    } else if (val < 32 || val > 127) {\n      // TODO: this is gross, the array wrapping/unwrapping thing\n      [newArr[index]] = toHex([val]);\n    } else {\n      newArr[index] = String.fromCharCode(val);\n    }\n  });\n  return newArr;\n}\n\n// TODO: make the objects instead of maps since nobody uses maps\nconst types = new Map([\n  [\n    'hex',\n    {\n      formatter: toHex,\n      defaultValue: '00',\n      css: 'hex',\n    },\n  ],\n  [\n    'static-hex',\n    {\n      formatter: toHex,\n      defaultValue: '',\n      css: 'static-hex',\n    },\n  ],\n  [\n    'plaintext',\n    {\n      formatter: toAscii,\n      defaultValue: '',\n      css: 'plaintext',\n    },\n  ],\n]);\n\nconst sections = new Map([\n  [\n    'bruteforce',\n    {\n      label: 'Bruteforce block',\n      type: 'hex',\n      explainer:\n        'The workspace of the attack. During the attack, this block is prepended to our target block.',\n    },\n  ],\n  [\n    'block',\n    {\n      label: 'Target block',\n      type: 'static-hex',\n      explainer: 'The ciphertext we are trying to crack. It never changes.',\n    },\n  ],\n  [\n    'intermediate',\n    {\n      label: 'Decrypted Data',\n      type: 'hex',\n      explainer:\n        'The decrypted target block data. This still needs to be XORed with the original IV block to get plaintext.',\n    },\n  ],\n  [\n    'original-iv',\n    {\n      label: 'Original IV',\n      type: 'static-hex',\n      explainer: 'The original IV block that came with our ciphertext. It never changes.',\n    },\n  ],\n  [\n    'plaintext',\n    {\n      label: 'Recovered Plaintext',\n      type: 'plaintext',\n      explainer:\n        'The result of XORing the decrypted data with the original IV block. Represented as ASCII instead of hex.',\n    },\n  ],\n]);\n\nconst remainingFrames = [];\n\nfunction createTable() {\n  const tableContainer = document.getElementById('table-container');\n  const tableElement = document.createElement('table');\n  tableElement.setAttribute('id', 'padding-oracle-table');\n  tableContainer.appendChild(tableElement);\n\n  let rowIndex = 0;\n  sections.forEach((val, sectionName) => {\n    const tableRowElement = tableElement.insertRow(rowIndex);\n    tableRowElement.setAttribute('id', `${sectionName}-row`);\n    tableRowElement.setAttribute('class', 'demo');\n\n    const tableRowCellSectionName = tableRowElement.insertCell(0);\n    tableRowCellSectionName.setAttribute(\n      'class',\n      `demo ${types.get(sections.get(sectionName).type).css}`\n    );\n    tableRowCellSectionName.setAttribute('id', sectionName);\n    tableRowCellSectionName.innerText = sections.get(sectionName).label;\n\n    tableRowElement.onmouseover = function insertExplainer() {\n      const explainerDiv = document.getElementById('explainer');\n      explainerDiv.innerText = sections.get(sectionName).explainer;\n    };\n    tableRowElement.onmouseout = function removeExplainer() {\n      const explainerDiv = document.getElementById('explainer');\n      explainerDiv.innerText = '';\n    };\n\n    const defaultCellValue = types.get(sections.get(sectionName).type).defaultValue;\n    for (let i = 0; i < _padding_oracle__WEBPACK_IMPORTED_MODULE_0__[\"blockLen\"]; i += 1) {\n      const tableRowCell = tableRowElement.insertCell(i + 1);\n      tableRowCell.setAttribute('class', `demo ${types.get(sections.get(sectionName).type).css}`);\n      tableRowCell.setAttribute('align', 'center');\n      tableRowCell.setAttribute('id', `${sectionName}-${i}`);\n      tableRowCell.innerText = defaultCellValue;\n    }\n    rowIndex += 1;\n  });\n}\n\nfunction updateTables(updateFrame) {\n  const sectionName = updateFrame.type;\n  const sectionData = updateFrame.data;\n\n  const formatterFunc = types.get(sections.get(sectionName).type).formatter;\n  const formattedData = formatterFunc(sectionData);\n\n  formattedData.forEach((val, i) => {\n    const tableElement = document.getElementById(`${sectionName}-${i}`);\n    tableElement.innerText = val;\n  });\n\n  const descriptionDiv = document.getElementById('description');\n  descriptionDiv.innerText = `Current step: ${updateFrame.description}`;\n}\n\nasync function getAnimationData() {\n  await Object(_padding_oracle__WEBPACK_IMPORTED_MODULE_0__[\"doTheAttack\"])();\n  return Object(_padding_oracle__WEBPACK_IMPORTED_MODULE_0__[\"getTheGlobalBlob\"])();\n}\n\nfunction resetAnimation() {\n  sections.forEach((val, sectionName) => {\n    const defaultCellValue = types.get(sections.get(sectionName).type).defaultValue;\n    for (let i = 0; i < _padding_oracle__WEBPACK_IMPORTED_MODULE_0__[\"blockLen\"]; i += 1) {\n      const tableRowCell = document.getElementById(`${sectionName}-${i}`);\n      tableRowCell.innerText = defaultCellValue;\n    }\n  });\n  remainingFrames.forEach((val) => {\n    clearTimeout(val);\n  });\n  remainingFrames.length = 0;\n}\n\nfunction animateOracleAttack() {\n  resetAnimation();\n  getAnimationData().then((animationData) => {\n    const animationSpeedMs = 30;\n\n    animationData.forEach((frame, i) => {\n      remainingFrames.push(\n        setTimeout(() => {\n          updateTables(frame);\n        }, i * animationSpeedMs)\n      );\n    });\n  });\n}\n\nfunction component() {\n  const tableContainer = document.createElement('div');\n  tableContainer.setAttribute('id', 'table-container');\n  document.body.appendChild(tableContainer);\n\n  const runButton = document.createElement('input');\n  runButton.setAttribute('type', 'submit');\n  runButton.setAttribute('value', 'Begin Padding Oracle Attack');\n  runButton.addEventListener('click', animateOracleAttack);\n  document.body.appendChild(runButton);\n\n  const explainerDiv = document.createElement('div');\n  explainerDiv.setAttribute('id', 'explainer');\n  explainerDiv.innerText = 'hover on a cell for an explanation';\n\n  const explainDiv = document.createElement('div');\n  explainDiv.innerText = 'Explain: ';\n\n  explainDiv.appendChild(explainerDiv);\n  document.body.appendChild(explainDiv);\n\n  const descriptionDiv = document.createElement('div');\n  descriptionDiv.setAttribute('id', 'description');\n  document.body.appendChild(descriptionDiv);\n\n  createTable();\n}\n\ndocument.body.onload = component();\n\n\n//# sourceURL=webpack:///./src/layout.js?");

/***/ }),

/***/ "./src/padding-oracle.js":
/*!*******************************!*\
  !*** ./src/padding-oracle.js ***!
  \*******************************/
/*! exports provided: blockLen, getTheGlobalBlob, decryptionOracleAttack, doTheAttack */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
eval("__webpack_require__.r(__webpack_exports__);\n/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, \"blockLen\", function() { return blockLen; });\n/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, \"getTheGlobalBlob\", function() { return getTheGlobalBlob; });\n/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, \"decryptionOracleAttack\", function() { return decryptionOracleAttack; });\n/* harmony export (binding) */ __webpack_require__.d(__webpack_exports__, \"doTheAttack\", function() { return doTheAttack; });\nconst blockLen = 16;\n\nlet massiveBlob = [];\nlet globalIndex = 0;\n\nasync function encryptAsync(iv, secret) {\n  const key = new TextEncoder('utf-8').encode('key key key keyy');\n  // TODO: need to do a looooot more error handling\n  const cryptoKey = await window.crypto.subtle.importKey(\n    'raw',\n    key,\n    {\n      name: 'AES-CBC',\n    },\n    true,\n    ['encrypt', 'decrypt']\n  );\n  const encrypted = await window.crypto.subtle.encrypt(\n    {\n      name: 'AES-CBC',\n      iv,\n    },\n    cryptoKey,\n    secret\n  );\n  return encrypted;\n}\n\nasync function decryptAsync(iv, ciphertext) {\n  const key = new TextEncoder('utf-8').encode('key key key keyy');\n  const cryptoKey = await window.crypto.subtle.importKey(\n    'raw',\n    key,\n    {\n      name: 'AES-CBC',\n    },\n    true,\n    ['encrypt', 'decrypt']\n  );\n  const decrypted = await window.crypto.subtle.decrypt(\n    {\n      name: 'AES-CBC',\n      iv,\n    },\n    cryptoKey,\n    ciphertext\n  );\n  return decrypted;\n}\n\nasync function isPaddedCorrectly(iv, ciphertext) {\n  const didDecrypt = await decryptAsync(iv, ciphertext).catch(() => {\n    return false;\n  });\n  if (didDecrypt === false) {\n    return false;\n  }\n  return true;\n}\n\nasync function addEventToGlobalBlob(sectionName, data, description) {\n  let wrapperData = new Uint8Array(blockLen);\n  if (data.length !== blockLen) {\n    data.forEach((val, i) => {\n      wrapperData[blockLen - 1 - i] = data[data.length - 1 - i];\n    });\n  } else {\n    wrapperData = data.slice();\n  }\n\n  massiveBlob[globalIndex] = {\n    type: sectionName,\n    data: wrapperData,\n    description,\n  };\n  globalIndex += 1;\n}\n\nfunction getTheGlobalBlob() {\n  return massiveBlob;\n}\n\nasync function getLastNBytes(block) {\n  // 1. pick a few random words r1,..rb\n  const r = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);\n  const rLastIdx = r.length - 1;\n  const origValue = r[rLastIdx];\n\n  /* eslint no-console: [\"error\", { allow: [\"warn\",\"error\"] }] */\n  if (r.length !== blockLen && block.length !== blockLen) {\n    console.error(r.length);\n    console.error(block.length);\n    throw new Error('bad length');\n  }\n\n  await addEventToGlobalBlob(\n    'block',\n    block,\n    \"The ciphertext we're trying to crack the last bytes of\"\n  );\n  await addEventToGlobalBlob('bruteforce', r, 'The initial fake IV');\n\n  /* eslint no-bitwise: [\"error\", { \"allow\": [\"^=\",\"^\"] }] */\n  // 1 ...and take i=0\n  for (let i = 0; i < 256; i += 1) {\n    // pick r=r1,...r(b-1), (rb^i)\n    r[rLastIdx] ^= i;\n\n    await addEventToGlobalBlob('bruteforce', r, 'Guessing last byte');\n\n    // 3. if asking the oracle about (r | y) fails, increment i and go back to the previous step\n    let res = await isPaddedCorrectly(r, block);\n    if (res === true) {\n      // 4. replace rb by (rb ^ i)\n      break;\n    }\n    // 4. (implied -- don't replace rb with (rb ^ i) for next iteration\n    r[rLastIdx] = origValue;\n  }\n  await addEventToGlobalBlob('bruteforce', r, 'Found last byte');\n\n  // 5. for n = b  down to 2, do\n  // (we actually want be to be the last index)\n  const b = blockLen - 1;\n  for (let n = b; n >= 2; n -= 1) {\n    //  a. take r=r1,...r(b-n), (r(b-n+1) ^ 1), r(b-n+2)...rb\n    const nextOrigValue = r[b - n + 1];\n    r[b - n + 1] ^= 1;\n\n    // This is a special case -- we're checking to see if our randomly made\n    // block happens to generate non-one padding\n    await addEventToGlobalBlob('bruteforce', r, 'Checking for non-1 padding');\n    //  b. if O(r|y) fails, stop and output (r(b-n+1)^n)...(rb ^ n)\n    const res = await isPaddedCorrectly(r, block);\n    if (res === false) {\n      const answer = new Uint8Array(b - (b - n + 1));\n      for (let j = b - n + 1; j <= b; j += 1) {\n        answer[b - j] = r[j] ^ n;\n      }\n      await addEventToGlobalBlob('intermediate', answer, 'Found non-1 padding');\n      return answer;\n    }\n    r[b - n + 1] = nextOrigValue;\n  }\n  // 6. output rb ^ 1\n  const answer = new Uint8Array(1);\n  answer[0] = r[b] ^ 1;\n  await addEventToGlobalBlob('intermediate', answer, 'Found last byte');\n  return answer;\n}\n\nasync function recoverNextByte(known, block) {\n  // Assuming we can get a(j) through a(b)\n  const ajb = known;\n  const ajbLen = ajb.length;\n\n  // Last index of b\n  const b = blockLen - 1;\n\n  // Where in the 16 bytes does a(j) begin?\n  const jIdx = b - ajbLen + 1;\n\n  // 1. take r(k) = a(k) ^ (b -j + 2) for k = j...b\n  const r = new Uint8Array(16);\n  for (let k = jIdx; k < blockLen; k += 1) {\n    r[k] = ajb[k - jIdx] ^ (b - jIdx + 2);\n  }\n\n  // 2. pick r1,....r(j-1) at random and take i=0\n  for (let i = 0; i < jIdx; i += 1) {\n    r[i] = 0;\n  }\n  await addEventToGlobalBlob('bruteforce', r, 'Created false IV for next byte recovery');\n\n  // 2. ... and take i=0\n  for (let i = 0; i < 256; i += 1) {\n    // 3. take r=r1...r(j-2), (r(j-1) ^ i), rj....rb\n    const origValue = r[jIdx - 1];\n    r[jIdx - 1] ^= i;\n    await addEventToGlobalBlob('bruteforce', r, 'Guessing next byte');\n\n    // 4. if asking oracle about r|y returns padding error then increment i and go back to the previous step\n    const isPaddedRight = await isPaddedCorrectly(r, block);\n    r[jIdx - 1] = origValue;\n    if (isPaddedRight === true) {\n      //  5. output r(j-1) ^ i ^ (b - j + 2)\n      const answer = r[jIdx - 1] ^ i ^ (b - jIdx + 2);\n      return answer;\n    }\n  }\n  throw new Error('Unable to recover byte');\n}\n\n// TODO: gross to pass in prev for the display here ;_;\nasync function getTheRestOfTheBlock(known, block, prev) {\n  // TODO: check how Js does param passing\n  const currentKnown = Array.from(known);\n  for (let i = blockLen - known.length; i > 0; i -= 1) {\n    let nextLetter = await recoverNextByte(new Uint8Array(currentKnown), block);\n    currentKnown.unshift(nextLetter);\n    await addEventToGlobalBlob('intermediate', currentKnown, 'Recovered another intermediate byte');\n\n    const showPlaintextAlongTheWay = new Uint8Array(blockLen);\n    for (let j = 0; j < currentKnown.length; j += 1) {\n      showPlaintextAlongTheWay[blockLen - 1 - j] =\n        currentKnown[currentKnown.length - 1 - j] ^ prev[blockLen - 1 - j];\n    }\n    await addEventToGlobalBlob(\n      'plaintext',\n      showPlaintextAlongTheWay,\n      'Recovered byte of plaintext'\n    );\n  }\n\n  return currentKnown;\n}\n\n// TODO: this func was separated out because it's helpful when brute forcing text\n// but it makes things messier if we are only demoing decryption. figure this out\nasync function decryptionOracleAttack(ciphertext) {\n  if (ciphertext.length % blockLen !== 0) {\n    throw new Error('wrong len');\n  }\n  // treat the prepended IV as a block\n  const numBlocks = ciphertext.length / blockLen;\n  const results = [];\n\n  for (let blockNumber = numBlocks; blockNumber > 1; blockNumber -= 1) {\n    const curBlock = ciphertext.slice((blockNumber - 1) * blockLen, blockNumber * blockLen);\n    if (curBlock.length !== blockLen) {\n      throw new Error('wrong block size');\n    }\n\n    const lastNBytes = await getLastNBytes(curBlock);\n\n    // doing a little side work to make the presentation nicer\n    const prevBlock = ciphertext.slice((blockNumber - 2) * blockLen, (blockNumber - 1) * blockLen);\n    const showPlaintextAlongTheWay = new Uint8Array(16);\n\n    // do this for last n bytes\n    for (let i = 0; i < lastNBytes.length; i += 1) {\n      showPlaintextAlongTheWay[blockLen - 1 - i] =\n        lastNBytes[lastNBytes.length - 1 - i] ^ prevBlock[blockLen - 1 - i];\n    }\n    await addEventToGlobalBlob(\n      'plaintext',\n      showPlaintextAlongTheWay,\n      'Recovered byte of plaintext'\n    );\n\n    const recovered = await getTheRestOfTheBlock(lastNBytes, curBlock, prevBlock);\n\n    Array.prototype.unshift.apply(results, recovered);\n  }\n\n  return results;\n}\n\nasync function xorTwoBlocks(iv, recovered) {\n  await addEventToGlobalBlob('intermediate', recovered, 'Got full block of intermediate');\n  if (iv.length !== recovered.length && recovered.length !== blockLen) {\n    console.error(iv.length);\n    console.error(recovered.length);\n    throw new Error('block size mismatch');\n  }\n\n  const plaintext = [];\n\n  for (let i = 0; i < blockLen; i += 1) {\n    plaintext[i] = iv[i] ^ recovered[i];\n  }\n\n  return plaintext;\n}\n\nasync function oracleAttack(ciphertext) {\n  // treat the prepended IV as a block\n  const numBlocks = ciphertext.length / blockLen;\n\n  const intermediate = await decryptionOracleAttack(ciphertext);\n\n  const plaintext = [];\n  for (let blockNumber = numBlocks; blockNumber > 1; blockNumber -= 1) {\n    const recovered = intermediate.slice(\n      (blockNumber - 2) * blockLen,\n      (blockNumber - 1) * blockLen\n    );\n    const prevBlock = ciphertext.slice((blockNumber - 2) * blockLen, (blockNumber - 1) * blockLen);\n    if (prevBlock.length !== blockLen && recovered.length !== blockLen) {\n      throw new Error('wrong block size');\n    }\n\n    const blockAnswer = await xorTwoBlocks(prevBlock, recovered);\n    plaintext.unshift(...blockAnswer);\n    await addEventToGlobalBlob('plaintext', plaintext, 'Plaintext recovered');\n  }\n\n  return plaintext;\n}\n\nasync function doTheAttack() {\n  massiveBlob = [];\n  globalIndex = 0;\n  const testIV = new TextEncoder('utf-8').encode('plain normal iv!');\n  const testSecrets = [\n    new TextEncoder('utf-8').encode('Hack the Planet'),\n    new TextEncoder('utf-8').encode('Crash Override'),\n    new TextEncoder('utf-8').encode('Padding Oracle'),\n    new TextEncoder('utf-8').encode('Super Mario RPG'),\n  ];\n  const testSecret = testSecrets[Math.floor(Math.random() * testSecrets.length)];\n  const ciphertext = new Uint8Array(await encryptAsync(testIV, testSecret));\n  await addEventToGlobalBlob('original-iv', testIV, 'The original input IV');\n  //await addEventToGlobalBlob('ciphertext', ciphertext, 'Input Ciphertext');\n\n  // TODO: next 2 lines are a total hackjob\n  const key = new TextEncoder('utf-8').encode('key key key keyy');\n  //await addEventToGlobalBlob('key', key, 'Secret key');\n\n  const ivPlusCiphertext = new Uint8Array(testIV.length + ciphertext.length);\n  ivPlusCiphertext.set(testIV);\n  ivPlusCiphertext.set(ciphertext, testIV.length);\n\n  await oracleAttack(ivPlusCiphertext);\n}\n\n// TODO: replace the below with unit tests in Jest framework\n/*\n// TODO: is there an easy test framework for JS to replace this with?\nasync function runTests() {\n  let testIV = new TextEncoder('utf-8').encode('that is an iv ma');\n  let testSecret = new TextEncoder('utf-8').encode('that is a cat, and that over there is a dog');\n\n  // test encryption\n  let ciphertext = new Uint8Array(await encryptAsync(testIV, testSecret));\n  let knownCiphertext = [\n    42,\n    25,\n    164,\n    144,\n    239,\n    196,\n    207,\n    189,\n    56,\n    99,\n    38,\n    160,\n    42,\n    118,\n    155,\n    228,\n    12,\n    8,\n    151,\n    245,\n    135,\n    2,\n    13,\n    175,\n    173,\n    211,\n    128,\n    147,\n    2,\n    80,\n    14,\n    208,\n    74,\n    5,\n    48,\n    246,\n    133,\n    74,\n    96,\n    175,\n    152,\n    62,\n    16,\n    181,\n    204,\n    149,\n    248,\n    53,\n  ];\n\n  if (ciphertext.length != knownCiphertext.length) {\n    console.error(ciphertext.length);\n    console.error(knownCiphertext.length);\n    return;\n  }\n  for (let i = 0; i < ciphertext.length; i++) {\n    if (ciphertext[i] != knownCiphertext[i]) {\n      console.error('arr not equal');\n      return;\n    }\n  }\n\n  // test decryption\n  let plaintext = new Uint8Array(await decryptAsync(testIV, ciphertext));\n  if (plaintext.length != testSecret.length) {\n    console.error(plaintext.length);\n    console.error(testSecret.length);\n    return;\n  }\n  for (let i = 0; i < plaintext.length; i++) {\n    if (plaintext[i] != testSecret[i]) {\n      console.error('arr not equal');\n      return;\n    }\n  }\n\n  // test padded correct\n  let isPaddedCorrectly1 = await isPaddedCorrectly(testIV, ciphertext);\n  if (isPaddedCorrectly1 != true) {\n    console.error(isPaddedCorrectly1);\n    return;\n  }\n\n  // test padded incorrect\n  let fakeIV = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];\n  let isPaddedCorrectly2 = await isPaddedCorrectly(fakeIV, ciphertext);\n  if (isPaddedCorrectly2 != false) {\n    console.error(isPaddedCorrectly2);\n    return;\n  }\n\n  //test getLastNBytes\n  let getLastCipher = new Uint8Array(await encryptAsync(testIV, testSecret));\n  let lastBlock = getLastCipher.slice(getLastCipher.length - blockLen, getLastCipher.length);\n  if (lastBlock.length != blockLen) {\n    console.error(lastBlock.length);\n    return;\n  }\n\n  let lastNBytes = await getLastNBytes(lastBlock);\n  if (lastNBytes.length != 1) {\n    console.error(lastNBytes.length);\n    return;\n  }\n  if (lastNBytes[0] != 213) {\n    console.error(lastNBytes[0]);\n    return;\n  }\n\n  //test recoverNextByte\n  let nextByte = await recoverNextByte(lastNBytes, lastBlock);\n  if (nextByte != 11) {\n    console.error(nextByte);\n    return;\n  }\n\n  //test getTheRestOfTheBlock\n  // note: dont use nextByte from above\n  let restOfTheBlock = await getTheRestOfTheBlock(lastNBytes, lastBlock);\n  let knownRestOfTheBlock = [\n    126,\n    109,\n    183,\n    156,\n    244,\n    34,\n    108,\n    143,\n    201,\n    188,\n    231,\n    150,\n    7,\n    85,\n    11,\n    213,\n  ];\n  if (restOfTheBlock.length != knownRestOfTheBlock.length) {\n    console.error(restOfTheBlock.length);\n    return;\n  }\n  for (let i = 0; i < restOfTheBlock.length; i++) {\n    if (restOfTheBlock[i] != knownRestOfTheBlock[i]) {\n      console.error('arr not equal');\n      return;\n    }\n  }\n\n  //test oracleAttack\n  let ivPlusCiphertext = new Uint8Array(testIV.length + ciphertext.length);\n  ivPlusCiphertext.set(testIV);\n  ivPlusCiphertext.set(ciphertext, testIV.length);\n\n  let oracle = await oracleAttack(ivPlusCiphertext);\n  let knownPaddedPlaintext = 'that is a cat, and that over there is a dog' + '\\x05\\x05\\x05\\x05\\x05';\n  if (oracle.length != knownPaddedPlaintext.length) {\n    console.error('wrong lengths');\n    console.error(oracle.length);\n    console.error(knownPaddedPlaintext.length);\n    return;\n  }\n\n  for (let i = 0; i < oracle.length; i++) {\n    if (oracle[i] != knownPaddedPlaintext.charCodeAt(i)) {\n      console.error('arr not equal');\n      return;\n    }\n  }\n\n  // to print our successful decoding:\n  // console.error(new TextDecoder(\"utf-8\").decode(new Uint8Array(oracle)))\n}\n*/\n\n\n//# sourceURL=webpack:///./src/padding-oracle.js?");

/***/ }),

/***/ "./src/style.css":
/*!***********************!*\
  !*** ./src/style.css ***!
  \***********************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

eval("var api = __webpack_require__(/*! ../node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js */ \"./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js\");\n            var content = __webpack_require__(/*! !../node_modules/css-loader/dist/cjs.js!./style.css */ \"./node_modules/css-loader/dist/cjs.js!./src/style.css\");\n\n            content = content.__esModule ? content.default : content;\n\n            if (typeof content === 'string') {\n              content = [[module.i, content, '']];\n            }\n\nvar options = {};\n\noptions.insert = \"head\";\noptions.singleton = false;\n\nvar update = api(content, options);\n\n\n\nmodule.exports = content.locals || {};\n\n//# sourceURL=webpack:///./src/style.css?");

/***/ })

/******/ });