/**
 * phish-triage for Gmail: a sidebar on the open email that sends it to my phish-triage API.
 *
 * Nothing runs until I click a button. Scan sends the open email to POST /v1/scan, Explain to POST /v1/explain
 * (Claude, on demand), and the feedback buttons send only the scan id and a label. "Send as phishing / legitimate"
 * is the one button that asks the API to keep the email: for retraining, for at most 90 days. The add-on keeps nothing but the
 * API address and my API key, in my own user properties; it logs nothing. It may call only the API address named in
 * the manifest (urlFetchWhitelist), and it reads only the open message (gmail.addons.current.message.readonly).
 */

var MAX_BYTES = 2 * 1024 * 1024; // the API refuses more
var LABELS = { correct: 'Correct', false_alarm: 'False alarm', missed_phish: 'Missed phishing' };

function onGmailMessageOpen(e) {
  if (!settings().ready) {
    return [settingsCard('Set the API address and your key first.')];
  }
  return [startCard()];
}

// --- Settings: the API address and my key, kept in my user properties only ---

function settings() {
  var props = PropertiesService.getUserProperties();
  var url = (props.getProperty('apiUrl') || '').replace(/\/+$/, '');
  var key = props.getProperty('apiKey') || '';
  return { url: url, key: key, ready: url.indexOf('https://') === 0 && key.length > 0 };
}

function settingsCard(message) {
  var current = settings();
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(message || 'Where the add-on sends emails, and with which key.'))
    .addWidget(CardService.newTextInput().setFieldName('apiUrl').setTitle('API address (https://...)').setValue(current.url))
    .addWidget(
      CardService.newTextInput()
        .setFieldName('apiKey')
        .setTitle(current.key ? 'API key (saved, ends in ' + current.key.slice(-4) + '; leave empty to keep)' : 'API key')
    )
    .addWidget(
      CardService.newTextButton().setText('Save').setOnClickAction(CardService.newAction().setFunctionName('saveSettings'))
    );
  return CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle('phish-triage settings')).addSection(section).build();
}

function saveSettings(e) {
  var form = e.commonEventObject && e.commonEventObject.formInputs ? e.commonEventObject.formInputs : {};
  var value = function (name) {
    var field = form[name];
    return field && field.stringInputs && field.stringInputs.value.length ? field.stringInputs.value[0].trim() : '';
  };
  var props = PropertiesService.getUserProperties();
  var url = value('apiUrl');
  if (url.indexOf('https://') !== 0) {
    return notify('The API address must start with https://');
  }
  props.setProperty('apiUrl', url.replace(/\/+$/, ''));
  var key = value('apiKey');
  if (key) {
    props.setProperty('apiKey', key);
  }
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText('Saved'))
    .setNavigation(CardService.newNavigation().updateCard(startCard()))
    .build();
}

// --- The cards ---

function startCard() {
  var section = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText('Nothing has been sent. Scan sends this email to my phish-triage API.'))
    .addWidget(
      CardService.newButtonSet()
        .addButton(CardService.newTextButton().setText('Scan').setOnClickAction(CardService.newAction().setFunctionName('scanMessage')))
        .addButton(CardService.newTextButton().setText('Settings').setOnClickAction(CardService.newAction().setFunctionName('openSettings')))
    );
  return CardService.newCardBuilder().setHeader(CardService.newCardHeader().setTitle('phish-triage')).addSection(section).build();
}

function openSettings(e) {
  return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().pushCard(settingsCard())).build();
}

var VERDICT_TEXT = {
  phish: 'Phishing',
  safe: 'Looks safe',
  review: 'Needs a closer look (too little text to judge)',
  suspicious: 'Suspicious',
  needs_human_review: 'Needs a closer look'
};

function scanMessage(e) {
  var email = openEmail(e);
  if (email.error) {
    return notify(email.error);
  }
  var answer = call('/v1/scan', email.raw);
  if (answer.error) {
    return notify(answer.error);
  }
  var v = answer.body;
  var result = CardService.newCardSection()
    .setHeader(VERDICT_TEXT[v.verdict] || v.verdict)
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel('Score (' + v.stage + ')')
        .setText(v.score.toFixed(4) + (v.phishing_above != null ? ', phishing above ' + v.phishing_above.toFixed(4) : ''))
    )
    .addWidget(CardService.newDecoratedText().setTopLabel('Sender check').setText(v.sender.verdict));
  (v.sender.warnings || []).forEach(function (w) {
    result.addWidget(CardService.newTextParagraph().setText('⚠ ' + w));
  });
  (v.signals || []).slice(0, 8).forEach(function (s) {
    result.addWidget(CardService.newTextParagraph().setText('• ' + s));
  });
  if (email.rebuilt) {
    result.addWidget(CardService.newTextParagraph().setText('<i>Read from the message parts, not the original source.</i>'));
  }
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('phish-triage').setSubtitle('Model ' + v.model_version))
    .addSection(result)
    .addSection(actionsSection(v.scan_id))
    .build();
  return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().pushCard(card)).build();
}

function actionsSection(scanId) {
  var explain = CardService.newTextButton()
    .setText('Explain (sends it to Claude)')
    .setOnClickAction(CardService.newAction().setFunctionName('explainMessage'));
  var feedback = CardService.newButtonSet();
  Object.keys(LABELS).forEach(function (label) {
    feedback.addButton(
      CardService.newTextButton()
        .setText(LABELS[label])
        .setOnClickAction(CardService.newAction().setFunctionName('sendFeedback').setParameters({ scanId: scanId, label: label }))
    );
  });
  var keep = CardService.newButtonSet();
  [['phish', 'Send as phishing'], ['legit', 'Send as legitimate']].forEach(function (choice) {
    keep.addButton(
      CardService.newTextButton()
        .setText(choice[1])
        .setOnClickAction(CardService.newAction().setFunctionName('sendForRetraining').setParameters({ label: choice[0] }))
    );
  });
  return CardService.newCardSection()
    .addWidget(explain)
    .addWidget(CardService.newTextParagraph().setText('Was the verdict right?'))
    .addWidget(feedback)
    .addWidget(
      CardService.newTextParagraph().setText('<b>Retraining:</b> keeps this email in my private bucket for at most 90 days.')
    )
    .addWidget(keep);
}

function sendForRetraining(e) {
  var label = e.commonEventObject.parameters.label;
  var email = openEmail(e);
  if (email.error) {
    return notify(email.error);
  }
  var answer = call('/v1/retraining-email?label=' + encodeURIComponent(label), email.raw);
  if (answer.error) {
    return notify(answer.error);
  }
  return notify('Kept for retraining as ' + (label === 'phish' ? 'phishing' : 'legitimate') + ' (deleted within 90 days)');
}

function explainMessage(e) {
  var email = openEmail(e);
  if (email.error) {
    return notify(email.error);
  }
  var answer = call('/v1/explain', email.raw);
  if (answer.error) {
    return notify(answer.error);
  }
  var x = answer.body;
  var section = CardService.newCardSection().setHeader(VERDICT_TEXT[x.verdict] || x.verdict);
  if (x.summary) {
    section.addWidget(CardService.newTextParagraph().setText(escapeHtml(x.summary)));
  }
  if (x.recommended_action) {
    section.addWidget(CardService.newDecoratedText().setTopLabel('What to do').setText(x.recommended_action.replace(/_/g, ' ')));
  }
  (x.indicators || []).forEach(function (i) {
    section.addWidget(
      CardService.newDecoratedText().setTopLabel(i.type).setText(escapeHtml(i.evidence)).setBottomLabel(escapeHtml(i.why)).setWrapText(true)
    );
  });
  (x.reasons || []).forEach(function (r) {
    section.addWidget(CardService.newTextParagraph().setText('<i>' + escapeHtml(r) + '</i>'));
  });
  var card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Explanation').setSubtitle(x.llm_model + '; nothing was stored'))
    .addSection(section)
    .build();
  return CardService.newActionResponseBuilder().setNavigation(CardService.newNavigation().pushCard(card)).build();
}

function sendFeedback(e) {
  var p = e.commonEventObject.parameters;
  var answer = call('/v1/feedback', JSON.stringify({ scan_id: p.scanId, label: p.label }), 'application/json');
  return notify(answer.error || 'Thanks: recorded "' + LABELS[p.label] + '"');
}

// --- Reading the open email and calling the API ---

function openEmail(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  var message = GmailApp.getMessageById(e.gmail.messageId);
  var raw;
  var rebuilt = false;
  try {
    raw = message.getRawContent(); // the original source, as "Show original" in Gmail
  } catch (err) {
    raw = rebuildEmail(message); // if this scope doesn't allow the source: headers and body from the parts
    rebuilt = true;
  }
  if (Utilities.newBlob(raw).getBytes().length > MAX_BYTES) {
    return { error: 'This email is larger than 2 MB; the API refuses it.' };
  }
  return { raw: raw, rebuilt: rebuilt };
}

function rebuildEmail(message) {
  var header = function (name) {
    try {
      return message.getHeader(name) || '';
    } catch (err) {
      return '';
    }
  };
  var lines = [];
  ['From', 'To', 'Cc', 'Reply-To', 'Subject', 'Date', 'Authentication-Results', 'Return-Path', 'Message-ID'].forEach(function (name) {
    var value = name === 'From' ? message.getFrom() : name === 'Subject' ? message.getSubject() : header(name);
    if (value) {
      lines.push(name + ': ' + String(value).replace(/[\r\n]+/g, ' '));
    }
  });
  var boundary = 'phish-triage-' + Utilities.getUuid();
  lines.push('MIME-Version: 1.0', 'Content-Type: multipart/alternative; boundary="' + boundary + '"', '');
  lines.push('--' + boundary, 'Content-Type: text/plain; charset=UTF-8', '', message.getPlainBody() || '');
  lines.push('--' + boundary, 'Content-Type: text/html; charset=UTF-8', '', message.getBody() || '');
  lines.push('--' + boundary + '--', '');
  return lines.join('\r\n');
}

function call(path, payload, contentType) {
  var s = settings();
  if (!s.ready) {
    return { error: 'Set the API address and key in Settings first.' };
  }
  var response;
  try {
    response = UrlFetchApp.fetch(s.url + path, {
      method: 'post',
      contentType: contentType || 'message/rfc822',
      payload: payload,
      headers: { 'x-api-key': s.key },
      muteHttpExceptions: true
    });
  } catch (err) {
    return { error: 'Could not reach the API (' + err.name + ').' };
  }
  var status = response.getResponseCode();
  var body = {};
  try {
    body = JSON.parse(response.getContentText());
  } catch (err) {
    body = {};
  }
  if (status === 200) {
    return { body: body };
  }
  var messages = {
    401: 'The API key was refused; check Settings.',
    413: 'The email is too large for the API.',
    429: body.detail || 'Too many requests; try again in a minute.',
    503: 'The model is loading (a cold start); try again in 30 seconds.'
  };
  return { error: messages[status] || 'The API answered ' + status + (body.detail ? ': ' + body.detail : '') };
}

function notify(text) {
  return CardService.newActionResponseBuilder().setNotification(CardService.newNotification().setText(text)).build();
}

function escapeHtml(text) {
  return String(text || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
