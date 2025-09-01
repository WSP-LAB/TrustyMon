const BROWSER_DEFAULT_SAMPLE_LENGTH = 40;
const COLLECT_URL = "http://[ip]:21100/collect"
const REPORT_URL = "http://[ip]:21100/report"
const TRUSTED = {
  HTML: 1,
  Script: 2,
  ScriptURL: 3
}

let sampleDict = {};
let hash_queue = [];

function _deleteNode(node) {
  const keys = Object.keys(node);
  let removed = 0;
  for(let i = 0; i < keys.length; i++) {
    const key = keys[i];
    if (node[key] !== null) {
      if (Object.getPrototypeOf(node[key]) === acorn.Node.prototype) {
        delete node[key];
        removed++;
      }
      else if (typeof node[key] == 'object') {
        const prevSize = Object.keys(node[key]).length;
        const t = _deleteNode(node[key]);
        if (prevSize == t) {
          delete node[key];
          removed++;
        }
      }
    }
  }
  return removed;
}

function _isBuiltIn(foo) {
  if (window[foo] === undefined) {
    return false;
  }

  const builtin = [
    'globalThis', 'Infinity', 'NaN', 'undefined',
    'Object', 'Function', 'Boolean', 'Symbol',
    'Error', 'AggregateError', 'EvalError', 'RangeError', 'ReferenceError',
    'SyntaxError', 'TypeError', 'URIError', 'InternalError',
    'Number', 'BigInt', 'Math', 'Date',
    'String', 'RegExp',
    'Array', 'Int8Array', 'Uint8Array', 'Uint8ClampedArray',
    'Int16Array', 'Uint16Array', 'Int32Array', 'Uint32Array',
    'BigInt64Array', 'BigUint64Array', 'Float32Array', 'Float64Array',
    'Map', 'Set', 'WeakMap', 'WeakSet',
    'ArrayBuffer', 'SharedArrayBuffer', 'DataView', 'Atomics', 'JSON',
    'WeakRef', 'FinalizationRegistry',
    'Iterator', 'AsyncIterator', 'Promise', 'GeneratorFunction',
    'AsyncGeneratorFunction', 'Generator', 'AsyncGenerator', 'AsyncFunction',
    'Reflect', 'Proxy', 'Intl',
  ];

  if (builtin.includes(foo)) {
    return true;
  }

  if (typeof window[foo] === 'object') {
    const constructorName = window[foo].constructor.name;

    const builtinObj = [
      'Window', 'HTMLDocument', 'History', 'Location',
      'Navigation', 'Navigator', 'Screen',
    ];

    if (builtinObj.includes(constructorName)) {
      return true;
    }
  }

  else if (typeof window[foo] === 'function') {
    // Convert function to string and check for [native code]
    const fnStr = Function.prototype.toString.call(window[foo]);
    if (/\[native code\]/.test(fnStr)) {
      return true;
    }

    // Check if the function has a prototype property
    if (foo.hasOwnProperty('prototype')) {
      return false;
    }
    return false;
  }
  return false;
}

function toAST(code) {
  let parsed = undefined;

  if (code.startsWith("#src|")) {
    return "[\"" + code.substr(5) + "\"]";
  }
  parsed = acorn.parse(code);

  walked = [];
  acorn.walk.full(parsed, function(node) {
      delete node.start;
      delete node.end;
      _deleteNode(node);

      switch(node.type) {
          case "Literal":
              delete node.raw;
              delete node.value;
              break;
          case "TemplateElement":
              delete node.value;
              break;
          case "Identifier":
              if (!_isBuiltIn(node.name)) {
                delete node.name;
                break;
              }
          default:
      }
      walked.push(node);
  });
  return JSON.stringify(walked);
}

function getURL() {
  url  = location.protocol + "//" + location.host + location.pathname;
  return url;
}

function initURL(url = '') {
  if (url == '')
    url  = getURL();
  if (typeof sampleDict[url] == 'undefined') {
    sampleDict[url] = {};
  }
  return url;
}

function isValid(type, hash){
  let c = getURL();
  try {
    if (_TT_WHITELISTS[hash] === 1) {
      return true;
    }
    return false;
  }
  catch {
    return false;
  }
}

const unsafeDOMParser = trustedTypes.createPolicy('unsafeDOMParser', {
  createHTML: string => string
});

function handleTrustedHTML(taintHTML) {
  let resultObj = parseDOMString(taintHTML);
  let astObj = []
  for(var i=0; i <resultObj.length; i++) {
    astObj.push(toAST(resultObj[i]))
  }

  let sha1 = getSHA1(JSON.stringify(astObj));
  return {asts: astObj, hash: sha1};
}

function handleTrustedScript(taintScript) {
  let astObj = []
  astObj.push(toAST(taintScript));
  console.log(JSON.stringify(astObj));

  let sha1 = getSHA1(JSON.stringify(astObj));
  console.log(sha1);
  return {asts: astObj, hash: sha1};
}

function handleTrustedScriptURL(taintURL) {
  isBlob = false;
  if (taintURL.startsWith("blob:")) {
    isBlob = true;
    taintURL = taintURL.split("blob:")[1];
  }
  if (taintURL.startsWith("http://") || taintURL.startsWith("https://")) {
    //do nothing
  }
  else if (taintURL.startsWith("//")) {
    taintURL = location.protocol + taintURL;
  }
  else {
    let path = location.pathname;
    let lastSlash = path.lastIndexOf("/");
    if (lastSlash == -1) {
      taintURL = location.origin + "/" + taintURL;
    }
    else {
      taintURL = location.origin + path.substr(0, lastSlash) + "/" + taintURL;
    }
  }
  taintURL = taintURL.split('?')[0];
  if (isBlob) {
    taintURL = "blob:" + taintURL;
  }

  return getSHA1(taintURL);
}

function getElementType(obj) {
  if (obj.tagName == 'A')
    return 'a';
  let proto = Object.getPrototypeOf(obj).toString().toLowerCase();
  let begin = proto.indexOf("html");
  return proto.slice(begin + 4, -8); // 'element]' : -8
}

/*
# need action
<a>.href
<form>.action
<button>.formAction
<input>.formAction
--------------
# execute when loading
<iframe>.src
<script>.src
window.location
location.assign()
location.replace()
----------------
# not executed in modern browser
<object>.data
<embed>.src
window.history.pushState()
window.history.replaceState()
*/

function parseDOMString(domString) {
  let resultObj = [];
  let parsed = (new DOMParser()).parseFromString(unsafeDOMParser.createHTML(domString), "text/html");
  let childNodes = parsed.children;

  for(let i = 0; i < childNodes.length; i++) {
    let curNode = childNodes[i];
    let attrs = curNode.getAttributeNames();

    if(getElementType(curNode) == 'script') {
      // Handle script
      if(curNode.innerHTML)
        resultObj.push(curNode.innerHTML);
      if(curNode.src)
        resultObj.push("#src|" + curNode.src);
    }
    else if(getElementType(curNode) == 'a') {
      // Handle A href
      if(curNode.href)
        if(curNode.href.toLowerCase().startsWith("javascript:"))
          resultObj.push(curNode.href.toLowerCase().substr(11));
    }
    else if(getElementType(curNode) == 'form') {
      // Handle form
      if(curNode.action)
        if(curNode.action.toLowerCase().startsWith("javascript:"))
          resultObj.push(curNode.action.toLowerCase().substr(11));
    }
    else if(getElementType(curNode) == 'button') {
      // Handle button
      if(curNode.formAction)
        if(curNode.formAction.toLowerCase().startsWith("javascript:"))
          resultObj.push(curNode.formAction.toLowerCase().substr(11));
    }
    else if(getElementType(curNode) == 'input') {
      // Handle input
      if(curNode.formAction)
        if(curNode.formAction.toLowerCase().startsWith("javascript:"))
          resultObj.push(curNode.formAction.toLowerCase().substr(11));
    }
    else if(getElementType(curNode) == 'iframe') {
      // Handle iframe

      if(curNode.srcdoc) {
        // Handle iframe srcdoc
        resultObj = resultObj.concat(parseDOMString(curNode.srcdoc));
      }
    }
    for(let j = 0; j < attrs.length; j++) {
      if (!attrs[j].startsWith('on'))
        continue;
      resultObj.push(curNode.getAttribute(attrs[j]));
    }

    for(let j = 0; j < curNode.children.length; j++) {
      resultObj = resultObj.concat(getDOMStructure(curNode.children[j]));
    }
  }

  return resultObj;

}

function getDOMStructure(curNode) {
  let attrs = curNode.getAttributeNames();
  let resultObj = [];

  if(getElementType(curNode) == 'script') {
    // Handle script
    if(curNode.innerHTML)
      resultObj.push(curNode.innerHTML);
    if(curNode.src)
      resultObj.push("#src|" + curNode.src);
  }
  else if(getElementType(curNode) == 'a') {
    // Handle A href
    if(curNode.href)
      if(curNode.href.toLowerCase().startsWith("javascript:"))
        resultObj.push(curNode.href.toLowerCase().substr(11));
  }
  else if(getElementType(curNode) == 'form') {
    // Handle form
    if(curNode.action)
      if(curNode.action.toLowerCase().startsWith("javascript:"))
        resultObj.push(curNode.action.toLowerCase().substr(11));
  }
  else if(getElementType(curNode) == 'button') {
    // Handle button
    if(curNode.formAction)
      if(curNode.formAction.toLowerCase().startsWith("javascript:"))
        resultObj.push(curNode.formAction.toLowerCase().substr(11));
  }
  else if(getElementType(curNode) == 'input') {
    // Handle input
    if(curNode.formAction)
      if(curNode.formAction.toLowerCase().startsWith("javascript:"))
        resultObj.push(curNode.formAction.toLowerCase().substr(11));
  }
  else if(getElementType(curNode) == 'iframe') {
    // Handle iframe

    if(curNode.srcdoc) {
      // Handle iframe srcdoc
      resultObj = resultObj.concat(parseDOMString(curNode.srcdoc));
    }
  }
  for(let j = 0; j < attrs.length; j++) {
    if (!attrs[j].startsWith('on'))
      continue;
    resultObj.push(curNode.getAttribute(attrs[j]));
  }

  for(let j = 0; j < curNode.children.length; j++) {
    resultObj = resultObj.concat(getDOMStructure(curNode.children[j]));
  }
  return resultObj;
}

function getSHA1(plaintext) {
  if (plaintext == "[]")
    return 'EMPTY';
  var md = forge.md.sha256.create();
  md.update(plaintext);
  return md.digest().toHex();
}

function parseViolationEvent(sample) {
  let t = sample.indexOf("|");

  if (sample.substr(0,t) == "Function") {
    s = "(function anonymous" + sample.substr(t+1);
    s = s.substr(0, BROWSER_DEFAULT_SAMPLE_LENGTH);
  }
  else {
    s = sample.substr(t+1);
  }
  let sampleList = sampleDict[getURL()][s];
  let hash = hash_queue.shift();

  for (let i=0; i<sampleList.length; i++) {
    let findSample = sampleList[i];

    if (findSample.hash == hash) {
      return [findSample.type, findSample.hash, findSample.content];
    }
  }

  return [-1, "", sample]
}

function collect(data) {
  console.log("collect e", data);
  fetch(COLLECT_URL, {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json'
    },
    mode: 'cors',
  });
}

function report(data) {
  console.log("Report e", data);
  fetch(REPORT_URL, {
    method: 'POST',
    body: JSON.stringify(data),
    headers: {
      'Content-Type': 'application/json'
    },
    mode: 'cors',
  });
}

document.addEventListener("securitypolicyviolation", (e) => {
  handleViolationEvent(e);
});

function update_dict(c, arg, item) {
  let sample = arg.trim().substr(0, BROWSER_DEFAULT_SAMPLE_LENGTH);
  if (sampleDict[c][sample] == undefined) {
    sampleDict[c][sample] = [item];
  }
  else if (!sampleDict[c][sample].includes(item)) {
    sampleDict[c][sample].push(item);
  }
}