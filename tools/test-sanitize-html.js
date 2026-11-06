// tools/test-sanitize-html.js
// Adversarial tests for the content backend's HTML sanitiser (lib/web-studio/sanitize-html.js).
//
// This module is the ONLY thing between an author-supplied article body and stored XSS on a
// published customer domain, because the `article` section renders body HTML unescaped. So the
// tests that matter here are the FAILURE paths: every case below is an attack that must not
// survive. A sanitiser suite that only proves "<p> is kept" proves nothing.
'use strict';
const assert = require('assert');
const { sanitizeHtml, htmlToText, safeUrl } = require('../lib/web-studio/sanitize-html');
const { t, finish } = require('./test-util').makeRunner();
// Assert a dangerous substring is absent from the OUTPUT, case-insensitively.
const absent = (out, needle, label) =>
  assert.ok(!out.toLowerCase().includes(needle.toLowerCase()), label + ' — found "' + needle + '" in: ' + out);

console.log('sanitize-html');

// ---------- script execution ------------------------------------------------------------------
t('drops <script> and its contents entirely', () => {
  const out = sanitizeHtml('<p>before</p><script>alert(1)</script><p>after</p>');
  absent(out, '<script', 'script tag survived');
  absent(out, 'alert(1)', 'script BODY leaked into the page as text');
  assert.ok(out.includes('before') && out.includes('after'), 'surrounding prose lost');
});

t('drops an UNCLOSED <script> through to end of input', () => {
  const out = sanitizeHtml('<p>ok</p><script>alert(1)');
  absent(out, 'alert(1)', 'unclosed script body survived');
});

t('drops <style>, <iframe>, <object>, <embed>, <form>, <svg> with content', () => {
  for (const tag of ['style', 'iframe', 'object', 'embed', 'form', 'svg']) {
    const out = sanitizeHtml('<' + tag + '>PAYLOAD</' + tag + '>');
    absent(out, 'PAYLOAD', tag + ' content survived');
    absent(out, '<' + tag, tag + ' tag survived');
  }
});

t('strips every on* event handler', () => {
  for (const h of ['onclick', 'onerror', 'onload', 'onmouseover', 'onfocus', 'onanimationstart']) {
    const out = sanitizeHtml('<p ' + h + '="alert(1)">x</p>');
    absent(out, h, h + ' survived');
    absent(out, 'alert(1)', h + ' payload survived');
  }
});

t('strips handlers with odd casing and whitespace before =', () => {
  const out = sanitizeHtml('<p OnClIcK = "alert(1)">x</p><img SRC=x OnErRoR="alert(1)">');
  absent(out, 'onclick', 'mixed-case handler survived');
  absent(out, 'onerror', 'mixed-case handler survived');
  absent(out, 'alert(1)', 'payload survived');
});

// ---------- URL schemes ------------------------------------------------------------------------
t('rejects javascript: hrefs but keeps the link text', () => {
  const out = sanitizeHtml('<a href="javascript:alert(1)">click</a>');
  absent(out, 'javascript:', 'javascript: URL survived');
  assert.ok(out.includes('click'), 'link text lost');
});

t('rejects obfuscated javascript: (entities, tabs, nulls, case, spaces)', () => {
  const vectors = [
    'JaVaScRiPt:alert(1)',
    '&#106;avascript:alert(1)',
    '&#x6a;avascript:alert(1)',
    'java\tscript:alert(1)',
    'java' + String.fromCharCode(0) + 'script:alert(1)',
    '  javascript:alert(1)',
    String.fromCharCode(1) + 'javascript:alert(1)',
    'java&Tab;script:alert(1)',
  ];
  for (const v of vectors) {
    const out = sanitizeHtml('<a href="' + v + '">x</a>');
    assert.ok(!/href/i.test(out), 'href survived for vector ' + JSON.stringify(v) + ': ' + out);
  }
});

t('rejects vbscript: and data:text/html', () => {
  for (const v of ['vbscript:msgbox(1)', 'data:text/html;base64,PHNjcmlwdD4=']) {
    const out = sanitizeHtml('<a href="' + v + '">x</a>');
    assert.ok(!/href/i.test(out), v + ' survived: ' + out);
  }
});

t('allows http, https, mailto, tel, fragments and relative paths', () => {
  for (const v of ['https://example.com/a', 'http://example.com', 'mailto:a@b.co', 'tel:+15551234',
    '#footnote-1', '/about/', './x', '../y']) {
    const out = sanitizeHtml('<a href="' + v + '">x</a>');
    assert.ok(out.includes('href='), 'safe URL was rejected: ' + v + ' -> ' + out);
  }
});

t('data: images only when explicitly enabled', () => {
  const img = '<img src="data:image/png;base64,iVBORw0KGgo=">';
  assert.ok(!/src=/i.test(sanitizeHtml(img)), 'data: image allowed by default');
  assert.ok(/src=/i.test(sanitizeHtml(img, { allowDataImage: true })), 'data: image rejected when enabled');
  // Even when enabled, a non-image data URL must not pass.
  const bad = '<img src="data:text/html;base64,PHNjcmlwdD4=">';
  assert.ok(!/src=/i.test(sanitizeHtml(bad, { allowDataImage: true })), 'data:text/html allowed as an image');
});

// ---------- parser confusion --------------------------------------------------------------------
t('drops comments, including conditional comments', () => {
  const out = sanitizeHtml('<p>a</p><!--[if IE]><script>alert(1)</script><![endif]--><p>b</p>');
  absent(out, 'alert(1)', 'conditional-comment payload survived');
  absent(out, '<!--', 'comment survived');
});

t('an unterminated comment cannot hide following markup', () => {
  const out = sanitizeHtml('<p>a</p><!-- <script>alert(1)</script>');
  absent(out, 'alert(1)', 'payload after unterminated comment survived');
});

t('a quoted ">" inside an attribute does not end the tag early', () => {
  const out = sanitizeHtml('<a href="/x" title="a > b">link</a>');
  assert.ok(out.includes('link'), 'text lost');
  absent(out, '<script', 'nothing injected');
});

t('mismatched and stray close tags produce well-formed output', () => {
  const out = sanitizeHtml('<p>a</b></p></div><em>b');
  assert.ok(out.includes('a') && out.includes('b'), 'text lost: ' + out);
  // Every emitted open tag must be closed.
  const opens = (out.match(/<(p|em|strong)\b[^>]*>/g) || []).length;
  const closes = (out.match(/<\/(p|em|strong)>/g) || []).length;
  assert.strictEqual(opens, closes, 'unbalanced output: ' + out);
});

t('unclosed tags at end of input are closed', () => {
  const out = sanitizeHtml('<p>a<em>b');
  assert.ok(out.endsWith('</em></p>') || /<\/em>\s*<\/p>$/.test(out), 'not closed: ' + out);
});

t('disallowed tags are dropped but their TEXT is kept', () => {
  const out = sanitizeHtml('<marquee>hello</marquee><blink>world</blink>');
  absent(out, '<marquee', 'marquee survived');
  assert.ok(out.includes('hello') && out.includes('world'), 'text inside dropped tags was lost');
});

t('bare < and stray text are escaped, not treated as markup', () => {
  const out = sanitizeHtml('5 < 6 and 7 > 2');
  assert.ok(out.includes('&lt;'), '< not escaped: ' + out);
});

// ---------- attribute handling -------------------------------------------------------------------
t('unquoted attribute values are handled', () => {
  const out = sanitizeHtml('<a href=/about/ title=hi>x</a>');
  assert.ok(out.includes('href="/about/"'), 'unquoted href lost: ' + out);
});

t('single-quoted attributes are handled', () => {
  const out = sanitizeHtml("<a href='/a' onclick='alert(1)'>x</a>");
  assert.ok(out.includes('href="/a"'), 'single-quoted href lost: ' + out);
  absent(out, 'onclick', 'handler survived');
});

t('attribute values are escaped so they cannot break out', () => {
  const out = sanitizeHtml('<a href="/x" title=\'a" onclick="alert(1)\'>x</a>');
  absent(out, 'onclick="alert', 'attribute breakout succeeded: ' + out);
});

t('target=_blank gains rel=noopener', () => {
  const out = sanitizeHtml('<a href="https://e.com" target="_blank">x</a>');
  assert.ok(/rel="noopener/.test(out), 'noopener not added: ' + out);
});

t('keeps id attributes (footnote anchors depend on them)', () => {
  const out = sanitizeHtml('<h2 id="federalist-57">No. 57</h2><a href="#federalist-57">jump</a>');
  assert.ok(out.includes('id="federalist-57"'), 'id lost — footnote/anchor links would break');
  assert.ok(out.includes('href="#federalist-57"'), 'fragment link lost');
});

// ---------- real recovered content must survive ---------------------------------------------------
t('preserves ordinary article markup intact', () => {
  const src = '<h2 id="s">Heading</h2><p>Some <strong>bold</strong> and <em>italic</em> text with a '
    + '<a href="https://example.com" rel="noopener" target="_blank">link</a>.</p>'
    + '<ul><li>one</li><li>two</li></ul><blockquote>quoted</blockquote>'
    + '<table><tr><th scope="col">h</th><td colspan="2">c</td></tr></table>';
  const out = sanitizeHtml(src);
  for (const frag of ['<h2 id="s">', '<strong>', '<em>', '<ul>', '<li>', '<blockquote>',
    '<table>', 'scope="col"', 'colspan="2"', 'href="https://example.com"']) {
    assert.ok(out.includes(frag), 'lost legitimate markup: ' + frag + '\n  got: ' + out);
  }
});

// These two regressions were found by running the sanitiser over 19 REAL recovered articles, not by
// the synthetic cases above — which all passed while genuine content was being corrupted.
t('does not double-escape existing entities', () => {
  const out = sanitizeHtml('<p>Tom &amp; Jerry &lt;tag&gt; &#39;q&#39; &nbsp;</p>');
  absent(out, '&amp;amp;', 'entity was double-escaped');
  absent(out, '&amp;lt;', 'entity was double-escaped');
  absent(out, '&amp;nbsp;', 'entity was double-escaped');
  assert.ok(out.includes('&amp;'), 'the ampersand entity was lost entirely: ' + out);
});

t('still escapes a BARE ampersand that is not an entity', () => {
  const out = sanitizeHtml('<p>a & b &notanentity</p>');
  assert.ok(out.includes('a &amp; b'), 'bare ampersand not escaped: ' + out);
});

t('entity-heavy content survives repeated sanitising unchanged', () => {
  let s = '<p>R&amp;D &mdash; &quot;x&quot; &#8212; caf&eacute;</p>';
  const once = sanitizeHtml(s);
  assert.strictEqual(sanitizeHtml(once), once, 'not idempotent with entities:\n  1: ' + once + '\n  2: ' + sanitizeHtml(once));
  assert.strictEqual(sanitizeHtml(sanitizeHtml(once)), once, 'drifts on a third pass');
});

t('keeps id on every allowed element (archival footnote anchors)', () => {
  for (const tag of ['sup', 'li', 'td', 'span', 'p', 'em', 'blockquote']) {
    const open = tag === 'li' ? '<ul><li id="fn-1">x</li></ul>'
      : tag === 'td' ? '<table><tr><td id="fn-1">x</td></tr></table>'
        : '<' + tag + ' id="fn-1">x</' + tag + '>';
    const out = sanitizeHtml(open);
    assert.ok(out.includes('id="fn-1"'), 'id dropped on <' + tag + '>: ' + out);
  }
});

t('is idempotent — sanitising twice changes nothing', () => {
  const src = '<p>a <a href="https://x.co" target="_blank">l</a></p><h3 id="z">t</h3>';
  const once = sanitizeHtml(src);
  assert.strictEqual(sanitizeHtml(once), once, 'not idempotent:\n  1: ' + once + '\n  2: ' + sanitizeHtml(once));
});

t('handles a large body without truncating by default', () => {
  const big = '<p>' + 'word '.repeat(50000) + '</p>';
  const out = sanitizeHtml(big);
  assert.ok(out.length > 200000, 'large body was truncated: ' + out.length);
});

t('maxLength truncates when asked', () => {
  const out = sanitizeHtml('<p>' + 'x'.repeat(5000) + '</p>', { maxLength: 100 });
  assert.ok(out.length < 200, 'maxLength ignored: ' + out.length);
});

// ---------- helpers --------------------------------------------------------------------------------
t('htmlToText strips markup and collapses whitespace', () => {
  assert.strictEqual(htmlToText('<p>a</p>\n<p>b   c</p>'), 'a b c');
  assert.strictEqual(htmlToText('<script>bad()</script><p>ok</p>'), 'ok');
});

t('safeUrl returns null for unsafe and the original for safe', () => {
  assert.strictEqual(safeUrl('javascript:alert(1)'), null);
  assert.strictEqual(safeUrl('https://a.b/c'), 'https://a.b/c');
  assert.strictEqual(safeUrl('#frag'), '#frag');
});

t('null and undefined are handled', () => {
  assert.strictEqual(sanitizeHtml(null), '');
  assert.strictEqual(sanitizeHtml(undefined), '');
  assert.strictEqual(htmlToText(null), '');
});

finish();
