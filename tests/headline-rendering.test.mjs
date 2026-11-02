import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { transformWithEsbuild } from 'vite';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { deriveHeadline, emptyHeadlineContext } from '../src/headline.js';
test('valid, rejected and conflicting displays have headline, one six-row ladder, then P4 insertion point',async()=>{
 const source=readFileSync(new URL('../src/EmployerReview.jsx',import.meta.url),'utf8');
 const block=source.slice(source.indexOf('export function HeadlineReview'),source.indexOf('const comparisons'));
 const {code}=await transformWithEsbuild(block,'HeadlineReview.jsx',{jsx:'automatic'});
 const runtime=pathToFileURL(createRequire(import.meta.url).resolve('react/jsx-runtime')).href;
 const {HeadlineReview}=await import('data:text/javascript;base64,'+Buffer.from(code.replace('"react/jsx-runtime"',JSON.stringify(runtime))).toString('base64'));
 const facts={parse:'OK',payload_hash:'MATCH',signatures:'VALID',chain:'VALID',continuity:'NONE',comparison:'NONE',reconciliation:'NONE',witness:'NONE'};
 for(const patch of [{},{parse:'INVALID_INPUT'},{comparison:'CONFLICT'}]){
  const headline=deriveHeadline({...facts,...patch},emptyHeadlineContext());
  const html=renderToStaticMarkup(createElement(HeadlineReview,{headline}));
  assert.equal((html.match(/data-evidence-ladder/g)||[]).length,1);assert.equal((html.match(/<dt>/g)||[]).length,6);
  assert.ok(html.indexOf('data-headline')<html.indexOf('data-evidence-ladder'));assert.ok(html.indexOf('data-evidence-ladder')<html.indexOf('data-statistics-insertion-point'));
  assert.ok(!/Sharpe|PSR|MinTRL|skew|kurtosis/.test(headline.headline+(headline.sublabel??'')));
 }
});
