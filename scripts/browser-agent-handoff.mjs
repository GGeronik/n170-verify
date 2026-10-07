import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {readFile, writeFile, mkdir, mkdtemp} from 'node:fs/promises';
import os from 'node:os';
import assert from 'node:assert/strict';
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const BASE=process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4174/';
const out=process.env.N170_EVIDENCE_DIR || path.join(ROOT,'docs/verification');await mkdir(out,{recursive:true});
const fixture=path.join(ROOT,'examples/agent-handoff-synthetic.json'), packet=JSON.parse(await readFile(fixture,'utf8'));
const browser=await chromium.launch();const context=await browser.newContext({viewport:{width:1440,height:1000},acceptDownloads:true});
const page=await context.newPage();const errors=[],tests=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
async function check(name,fn){await fn();tests.push({name,status:'passed'});console.log('PASS',name);}
try{
await page.goto(BASE);await page.getByText('Private draft up to date',{exact:true}).waitFor();
await check('Production entry exposes a readable prompt and return box without opening disclosures',async()=>{
  assert.equal(new URL(page.url()).origin,new URL(BASE).origin);assert.match(await page.title(),/N170 Verify/);
  assert.equal(await page.getByRole('button',{name:'Ask your AI',exact:true}).getAttribute('aria-pressed'),'true');
  assert.equal(await page.getByLabel('Prompt for your AI',{exact:true}).isVisible(),true);
  assert.equal(await page.getByLabel('Prompt for your AI',{exact:true}).getAttribute('readonly'),'');
  assert.equal(await page.getByLabel('Or paste your AI’s reply',{exact:true}).isVisible(),true);
  assert.equal(await page.locator('vite-error-overlay').count(),0);
});
await page.screenshot({path:path.join(out,'ai-prompt-entry-desktop.png'),fullPage:true});
await context.grantPermissions(['clipboard-read','clipboard-write']);
await check('Copy and download exactly match the visible complete prompt',async()=>{
  const visible=await page.getByLabel('Prompt for your AI',{exact:true}).inputValue();
  await page.getByRole('button',{name:'Copy prompt',exact:true}).click();await page.getByText('Copied. Paste it into the AI where your broker is connected.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),visible);
  const promise=page.waitForEvent('download');await page.getByRole('button',{name:'Download prompt',exact:true}).click();
  const target=path.join(out,'agent-instructions-downloaded.txt');await(await promise).saveAs(target);
  const text=await readFile(target,'utf8');assert.equal(text,visible);assert.match(text,/"schema_version"/);assert.match(text,/"source_ref"/);assert.match(text,/synthetic/);
});
await check('Select prompt and clipboard failure keep the full prompt directly copyable',async()=>{
  const box=page.getByLabel('Prompt for your AI',{exact:true});await page.getByRole('button',{name:'Select prompt',exact:true}).click();
  assert.deepEqual(await box.evaluate(el=>[el.selectionStart,el.selectionEnd,document.activeElement===el]),[0,(await box.inputValue()).length,true]);
  await page.evaluate(()=>{window.originalClipboardWrite=navigator.clipboard.writeText;navigator.clipboard.writeText=async()=>{throw new DOMException('Injected clipboard permission failure','NotAllowedError');};});
  await page.getByRole('button',{name:'Copy prompt again',exact:true}).click();await page.getByText(/Clipboard unavailable/).waitFor();
  assert.deepEqual(await box.evaluate(el=>[el.selectionStart,el.selectionEnd,document.activeElement===el]),[0,(await box.inputValue()).length,true]);
  await page.evaluate(()=>{navigator.clipboard.writeText=window.originalClipboardWrite;delete window.originalClipboardWrite;});
});
const reply='```json\n'+JSON.stringify(packet,null,2)+'\n```';
await page.getByLabel('Or paste your AI’s reply',{exact:true}).fill(reply);
await check('Changing entry routes preserves the pasted reply and unsaved status',async()=>{
  await page.getByRole('button',{name:'Import a file',exact:true}).click();await page.getByText('Choose export file',{exact:true}).waitFor();
  await page.getByRole('button',{name:'Ask your AI',exact:true}).click();assert.equal(await page.getByLabel('Or paste your AI’s reply',{exact:true}).inputValue(),reply);
  await page.getByText('Unsaved private draft',{exact:true}).waitFor();
});
await check('Unloaded pasted data is protected on navigation',async()=>{await page.getByRole('button',{name:'Review a record',exact:true}).click();await page.getByRole('dialog').waitFor();await page.getByRole('button',{name:'Keep editing',exact:true}).click();assert.match(await page.getByLabel('Or paste your AI’s reply').inputValue(),/n170.agent-handoff/);});
await check('Extra prose is rejected without losing the reply; one JSON code block is accepted',async()=>{
  await page.getByLabel('Or paste your AI’s reply',{exact:true}).fill('Here is your record:\n'+reply);
  await page.getByRole('button',{name:'Review my record',exact:true}).click();await page.getByText(/Paste one complete JSON handoff/).waitFor();
  assert.equal(await page.getByLabel('Or paste your AI’s reply',{exact:true}).inputValue(),'Here is your record:\n'+reply);
  await page.getByLabel('Or paste your AI’s reply',{exact:true}).fill(reply);
  await page.getByRole('button',{name:'Review my record',exact:true}).click();await page.getByText('Assistant-reported source · review privately',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>document.activeElement.textContent),'Reconciliation');
  assert.equal(await page.getByLabel('Prompt for your AI',{exact:true}).isVisible(),false);
});
await check('Owner sees private metadata and values before approval',async()=>{await page.getByText('Assistant-reported source · review privately',{exact:true}).waitFor();assert.equal(await page.locator('tbody tr').count(),packet.observations.length);assert.match(await page.locator('tbody').innerText(),new RegExp(packet.observations[0].nav.replace('.','\\.')));assert.equal(await page.getByRole('button',{name:'Review calculation',exact:true}).isEnabled(),false);assert.equal(await page.getByRole('button',{name:'Correct row 1',exact:true}).isEnabled(),false);await page.getByText('Observation references · private',{exact:true}).click();assert.match(await page.locator('body').innerText(),/not independently witnessed/);});
await page.screenshot({path:path.join(out,'handoff-owner-desktop.png'),fullPage:true});
await check('Review and reconciliation accept actual canonical observations',async()=>{await page.getByRole('checkbox',{name:/I reviewed the assistant/}).check();await page.getByRole('button',{name:'Reconcile file',exact:true}).click();await page.getByText(/Reconciliation complete/).waitFor();assert.equal(await page.getByRole('button',{name:'Review calculation',exact:true}).isEnabled(),true);});
await page.getByRole('button',{name:'Save draft',exact:true}).click();await page.getByText(/Private draft saved in this browser/).waitFor();await page.reload();await page.getByText(/Saved private draft restored/).waitFor();
await check('Save and reload retain handoff scope, mappings, review and synthetic status',async()=>{assert.equal(await page.locator('tbody tr').count(),packet.observations.length);assert.equal(await page.getByRole('checkbox',{name:/I reviewed the assistant/}).isChecked(),true);await page.getByText('Synthetic example · no real account',{exact:true}).waitFor();assert.equal(await page.getByLabel('Reporting currency',{exact:true}).isEnabled(),false);});
await page.getByRole('button',{name:'Review calculation',exact:true}).click();await page.getByRole('heading',{name:'Review before you sign',exact:true}).waitFor();assert.match(await page.locator('.metrics').innerText(),/1.00%/);
await page.getByLabel('Public profile alias',{exact:true}).fill('Synthetic assistant workflow');await page.getByRole('button',{name:'Create profile',exact:true}).click();await page.getByText(/Profile created and saved/).waitFor();await page.getByRole('checkbox',{name:/I reviewed the calculation/}).check();await page.getByRole('button',{name:'Sign record & save',exact:true}).click();await page.getByRole('heading',{name:'Ready for a thoughtful review.',exact:true}).waitFor();
const dp=page.waitForEvent('download');await page.getByRole('button',{name:'Download review package',exact:true}).click();const report=path.join(out,'agent-handoff-review.html');await(await dp).saveAs(report);
await check('Sharing carries honest provenance without private tool metadata',async()=>{const html=await readFile(report,'utf8');assert.match(html,/Assistant-prepared handoff/);assert.equal(html.includes(packet.source.connector),false);assert.equal(html.includes(packet.observations[0].source_ref),false);assert.match(html,/live\/paper status unchecked/);});
await page.getByRole('button',{name:'Open employer review',exact:true}).click();await page.getByRole('heading',{name:'Open a performance record',exact:true}).waitFor();await page.getByRole('button',{name:'Check record',exact:true}).click();
await check('Employer independently checks supplied handoff record',async()=>{await page.getByRole('heading',{name:'Synthetic assistant workflow',exact:true}).waitFor();assert.match(await page.locator('body').innerText(),/Assistant-prepared handoff · supplied file/);assert.match(await page.locator('body').innerText(),/No prior publication checked/);});
await page.screenshot({path:path.join(out,'handoff-employer-desktop.png'),fullPage:true});
const context2=await browser.newContext({viewport:{width:390,height:844}}),p2=await context2.newPage();await p2.goto(BASE);await p2.getByText('Private draft up to date',{exact:true}).waitFor();await p2.screenshot({path:path.join(out,'ai-prompt-entry-mobile.png'),fullPage:true});await check('Mobile prompt is readable, selectable and contained',async()=>{await p2.getByRole('button',{name:'Select prompt',exact:true}).click();assert.equal(await p2.getByLabel('Prompt for your AI',{exact:true}).evaluate(el=>document.activeElement===el),true);assert.equal(await p2.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);});const dir=await mkdtemp(path.join(os.tmpdir(),'n170-agent-ui-'));const blocked=structuredClone(packet);blocked.coverage.pagination='unknown';blocked.coverage.missing_periods=[{start:packet.requested_period.start,end:packet.requested_period.end,reason:'Cash activity pages unavailable'}];const file=path.join(dir,'blocked.json');await writeFile(file,JSON.stringify(blocked));await p2.locator('input[type=file]').setInputFiles(file);
await check('JSON file import cannot override missing MCP pages by confirming review',async()=>{await p2.getByRole('checkbox',{name:/I reviewed the assistant/}).check();await p2.getByRole('button',{name:'Reconcile file',exact:true}).click();await p2.getByText('Cash activity pages unavailable',{exact:false}).waitFor();assert.equal(await p2.getByRole('button',{name:'Review calculation',exact:true}).isEnabled(),false);assert.match(await p2.locator('body').innerText(),/unknown pagination/);});
await p2.screenshot({path:path.join(out,'handoff-blocked-mobile.png'),fullPage:true});await check('Mobile handoff review has no page overflow',async()=>{const sizes=await p2.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,offenders:[...document.querySelectorAll('body *')].filter(e=>e.getBoundingClientRect().right>innerWidth+1).map(e=>({tag:e.tagName,class:e.className,right:Math.round(e.getBoundingClientRect().right)})).slice(0,15)}));assert(sizes.scroll<=sizes.width,JSON.stringify(sizes));});await p2.screenshot({path:path.join(out,'handoff-blocked-mobile.png'),fullPage:true});
const context3=await browser.newContext({viewport:{width:1280,height:900}}),p3=await context3.newPage();await p3.goto(BASE);await p3.getByText('Private draft up to date',{exact:true}).waitFor();
const {importStatement}=await import('../src/importer.js');const {createEmptyDraft}=await import('../src/draftModel.js');const accepted=await importStatement(JSON.stringify(packet),{currency:packet.currency,frequency:packet.frequency,flowTimingConfirmed:true});const external={kind:'n170.private-draft.v1',data:{...createEmptyDraft(),original:JSON.stringify(packet),input:accepted.normalizedCsv,format:'agent-handoff',currency:packet.currency,frequency:String(packet.frequency),scope:packet.account_scope,synthetic:packet.synthetic,flowTimingConfirmed:true,importReview:accepted}};const externalPath=path.join(dir,'externally-reviewed-draft.json');await writeFile(externalPath,JSON.stringify(external));await p3.locator('input[type=file]').setInputFiles(externalPath);
await check('Externally supplied private draft cannot carry owner approval into the app',async()=>{await p3.getByText(/Source review must be confirmed again/).waitFor();assert.equal(await p3.getByRole('checkbox',{name:/I reviewed the assistant/}).isChecked(),false);assert.equal(await p3.getByRole('button',{name:'Review calculation',exact:true}).isEnabled(),false);});
await p3.getByRole('button',{name:'Save draft',exact:true}).click();await p3.getByText(/Private draft saved in this browser/).waitFor();const invalidEncoding=path.join(dir,'invalid-encoding.json');await writeFile(invalidEncoding,Buffer.from([0x7b,0x22,0xff,0x22,0x3a,0x30,0x7d]));await p3.getByRole('button',{name:'Import a file',exact:true}).click();await p3.locator('input[type=file]').setInputFiles(invalidEncoding);await check('Invalid UTF-8 rejected while current private draft is retained',async()=>{await p3.getByText(/not valid UTF-8/).waitFor();assert.equal(await p3.locator('tbody tr').count(),packet.observations.length);});
await check('Save and continue keeps editing disabled until the incoming handoff finishes opening',async()=>{
  const delayedContext=await browser.newContext({viewport:{width:1280,height:900}}),delayedPage=await delayedContext.newPage();
  delayedPage.on('pageerror',e=>errors.push(e.message));
  try{
    await delayedPage.goto(BASE);await delayedPage.getByText('Private draft up to date',{exact:true}).waitFor();
    await delayedPage.getByRole('button',{name:'Import a file',exact:true}).click();
    await delayedPage.getByRole('button',{name:'Try a synthetic example',exact:true}).click();
    await delayedPage.getByRole('button',{name:'Ask your AI',exact:true}).click();
    const replyBox=delayedPage.getByLabel('Or paste your AI’s reply',{exact:true});
    const incoming=JSON.stringify(packet,null,2);await replyBox.fill(incoming);
    await delayedPage.getByRole('button',{name:'Review my record',exact:true}).click();await delayedPage.getByRole('dialog').waitFor();
    // Pause only the incoming handoff's source hash. Saving the existing CSV draft
    // still completes, so the assertion covers the asynchronous action after save.
    await delayedPage.evaluate(()=>{
      const original=crypto.subtle.digest.bind(crypto.subtle);
      let release;const gate=new Promise(resolve=>{release=resolve;});
      window.n170DelayedDigest={waiting:false,release,restore:()=>{crypto.subtle.digest=original;}};
      crypto.subtle.digest=async(algorithm,data)=>{
        if(new TextDecoder().decode(data).includes('n170.agent-handoff.v1')){
          window.n170DelayedDigest.waiting=true;await gate;
        }
        return original(algorithm,data);
      };
    });
    await delayedPage.getByRole('button',{name:'Save draft & continue',exact:true}).click();
    await delayedPage.getByRole('dialog').waitFor({state:'hidden'});
    await delayedPage.waitForFunction(()=>window.n170DelayedDigest.waiting);
    // Flush React's busy-state update while the handoff remains deliberately pending.
    await delayedPage.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
    assert.equal(await replyBox.isEnabled(),false,'An in-flight replacement must not accept text that it will subsequently clear');
    assert.equal(await delayedPage.getByRole('button',{name:'Opening…',exact:true}).isEnabled(),false);
    await assert.rejects(()=>replyBox.fill('Synthetic new work during opening',{timeout:150}),/Timeout|not enabled/);
    assert.equal(await replyBox.inputValue(),incoming,'Blocked editing must preserve the pending original reply');
    await delayedPage.evaluate(()=>window.n170DelayedDigest.release());
    await delayedPage.getByText('Assistant-reported source · review privately',{exact:true}).waitFor();
    await delayedPage.getByRole('checkbox',{name:/I reviewed the assistant/}).waitFor();
    await delayedPage.waitForFunction(()=>!document.querySelector('#agent-handoff-json').disabled);
    assert.equal(await delayedPage.locator('tbody tr').count(),packet.observations.length);
    await delayedPage.getByText('Prepare another record with your AI',{exact:true}).click();
    assert.equal(await replyBox.isEnabled(),true);assert.equal(await replyBox.inputValue(),'');
  }finally{
    await delayedPage.evaluate(()=>{window.n170DelayedDigest?.release();window.n170DelayedDigest?.restore();}).catch(()=>{});
    await delayedContext.close();
  }
});
await check('No browser errors',async()=>assert.deepEqual(errors,[]));
await writeFile(path.join(out,'agent-handoff-browser-results.json'),JSON.stringify({date:'2026-09-14',browser:await browser.version(),url:BASE,viewports:['1440x1000','390x844','1280x900'],browser_plugin:'Browser plugin skill absent; existing Playwright harness used for repeatable production testing. Native in-app preview reviewed separately.',tests,errors},null,2));
}finally{await browser.close();}
