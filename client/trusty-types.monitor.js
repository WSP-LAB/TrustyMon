const trustedTypesCallbacks = trustedTypes.createPolicy('default', {
  createHTML: function(htmlString) {
    htmlString = htmlString.trim();
    let x = handleTrustedHTML(htmlString);
    let hash = x.hash
    if (x.asts.length == 0) return htmlString;
    let c = initURL();

    let new_item = {
      type: TRUSTED.HTML,
      hash: hash,
      content: htmlString
    };

    update_dict(c, htmlString, new_item);

    if (isValid(TRUSTED.HTML, hash)) {
      return htmlString;
    }
    else {
      hash_queue.push(hash);
      return;
    }
  },
  createScript: function(script) {
    let x = handleTrustedScript(script);
    let c = initURL();
    let hash = x.hash;
    if (c == '[]') return script;

    let new_item = {
      type: TRUSTED.Script,
      hash: hash,
      content: script
    };

    update_dict(c, script, new_item);

    if (isValid(TRUSTED.Script, hash)) {
      return script;
    }
    else {
      hash_queue.push(hash);
      return;
    }
  },
  createScriptURL: function(scriptURL) {
    let hash = handleTrustedScriptURL(scriptURL);
    let c = initURL();

    let new_item = {
      type: TRUSTED.ScriptURL,
      hash: hash,
      content: scriptURL
    };

    update_dict(c, scriptURL, new_item);

    if (isValid(TRUSTED.ScriptURL, hash)) {
      return scriptURL;
    }
    else {
      hash_queue.push(hash);
      return;
    }
  }
})

function handleViolationEvent(e) {
  let url = getURL();
  if (sampleDict[url] == undefined) {
    return;
  }
  let [type, hash, content] = parseViolationEvent(e.sample);
  report({
    t_type: type,
    t_hash: hash,
    t_content: content,
    t_sink: e.sample.split('|')[0],
    t_sample: e.sample,
    t_domain : e.documentURI,
    t_loc: `${e.lineNumber}#${e.columnNumber}#${e.sourceFile}`,
  });
}
