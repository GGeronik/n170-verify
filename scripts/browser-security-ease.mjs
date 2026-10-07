import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {generateProfileKey,createSigner} from '../src/signing.js';
import {createProfile,appendPerformanceStamp,provenanceFromImport,profileKeyCode} from '../src/trackRecord.js';
import {importStatement} from '../src/importer.js';

const {chromium}=await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const BASE=process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4174/';
assert(['127.0.0.1','localhost','[::1]'].includes(new URL(BASE).hostname),'Run only against a local production preview');
const out=process.env.N170_EVIDENCE_DIR || path.join(ROOT,'docs/verification');await mkdir(out,{recursive:true});
const fixture=JSON.parse(await readFile(path.join(ROOT,'examples/agent-handoff-synthetic.json'),'utf8'));
const browser=await chromium.launch();const contexts=[];const tests=[],errors=[],externalRequests=[];let currentPage;
async function makePage(viewport={width:1440,height:1000}){
  const context=await browser.newContext({viewport});contexts.push(context);
  await context.route('**/*',route=>{
    const url=route.request().url();
    if(new URL(url).origin===new URL(BASE).origin)return route.continue();
    externalRequests.push(url);return route.abort('blockedbyclient');
  });
  await context.addInitScript(()=>{window.n170Injected=0;});
  const page=await context.newPage();currentPage=page;
  page.on('pageerror',error=>errors.push(error.message));
  page.on('console',message=>{if(message.type()==='error')errors.push(message.text());});
  await page.goto(BASE);await page.getByText('Private draft up to date',{exact:true}).waitFor();
  return page;
}
async function check(name,fn){
  try{await fn();tests.push({name,status:'passed'});console.log('PASS',name);}
  catch(error){tests.push({name,status:'failed',error:error.message});throw error;}
}
async function inert(page){
  assert.deepEqual(await page.evaluate(()=>({executed:window.n170Injected,polluted:Object.prototype.n170Polluted??null})),{executed:0,polluted:null});
  assert.equal(await page.locator('[src*="invalid.test"],#n170-injected').count(),0);
  assert.deepEqual(externalRequests,[]);
}
async function checkRecord(page,text,name='synthetic-record.json'){
  await page.locator('input[type=file]').first().setInputFiles({name,mimeType:name.endsWith('.html')?'text/html':'application/json',buffer:Buffer.from(text)});
  await page.getByRole('button',{name:'Check record',exact:true}).click();
}
async function expectRejectedRecord(page,text,pattern,name){
  await checkRecord(page,text,name);const alert=page.getByRole('alert').first();await alert.waitFor();
  assert.match(await alert.innerText(),pattern);assert.equal(await page.locator('.review-result').count(),0);await inert(page);
}

const hostile=structuredClone(fixture);
hostile.source.broker='<script>window.n170Injected=1</script>';
hostile.source.retrieved_at='2024-03-19T04:27:31.123Z';
hostile.source.connector='PRIVATE_CONNECTOR<img src=https://invalid.test/c>';
hostile.source.tools=['PRIVATE_TOOL_<svg onload=window.n170Injected=1>'];
hostile.account_scope='PRIVATE_SCOPE_<b id=n170-injected>Source claim only</b>';
hostile.mapping={date:'PRIVATE_MAPPING_DATE',nav:'PRIVATE_MAPPING_NAV',external_flow:'PRIVATE_MAPPING_FLOW'};
hostile.observations.forEach((row,i)=>{row.source_ref=`PRIVATE_REFERENCE_${i}`;row.nav=['987654.321987','998000.456789','1005000.123456','1000000.987654'][i];});
hostile.observations[2].external_flow='2345.678912';
hostile.coverage.pagination='unknown';
hostile.coverage.missing_periods=[{...hostile.requested_period,reason:'PRIVATE_REASON_<img src=https://invalid.test/r onerror=window.n170Injected=1>'}];
hostile.coverage.unsupported_events=['PRIVATE_EVENT_<script>window.n170Injected=1</script>'];
hostile.flow_timing='unknown';
const sourceText=JSON.stringify(hostile,null,2);

try{
  const owner=await makePage();
  await check('Production page identity, meaningful content and no framework overlay',async()=>{
    assert.equal(new URL(owner.url()).origin,new URL(BASE).origin);assert.match(await owner.title(),/N170 Verify/);
    assert.equal(await owner.getByLabel('Prompt for your AI',{exact:true}).isVisible(),true);
    assert.equal(await owner.locator('vite-error-overlay').count(),0);
  });
  await owner.getByLabel('Or paste your AI’s reply',{exact:true}).fill(sourceText);
  await owner.getByRole('button',{name:'Review my record',exact:true}).click();
  await owner.getByText('Assistant-reported source · review privately',{exact:true}).waitFor();
  await check('Hostile broker, connector, tool and missing-evidence labels render as inert text',async()=>{
    const body=await owner.locator('body').innerText();
    for(const value of [hostile.source.broker,hostile.source.connector,hostile.source.tools[0],hostile.coverage.missing_periods[0].reason,hostile.coverage.unsupported_events[0]])assert(body.includes(value));
    assert.equal(await owner.getByLabel('Accounts covered, using public aliases',{exact:true}).inputValue(),hostile.account_scope);
    await inert(owner);
  });
  await check('Repair prompt is readable and copies exactly without private source content',async()=>{
    const prompt=owner.locator('#repair-prompt');await prompt.waitFor();assert.equal(await prompt.getAttribute('readonly'),'');
    const text=await prompt.inputValue();assert(text.length>100);assert.match(text,/pag(e|ination)|missing|observations/i);
    for(const secret of ['PRIVATE_','invalid.test','n170Injected',hostile.source.retrieved_at,...hostile.observations.map(row=>row.nav),'2345.678912'])assert(!text.includes(secret),`Repair prompt leaked ${secret}`);
    assert(!text.includes(sourceText));assert(!text.includes('<script>'));assert(!text.includes('<img'));
    await owner.context().grantPermissions(['clipboard-read','clipboard-write']);
    await owner.getByRole('button',{name:'Copy what needs fixing',exact:true}).click();
    await owner.waitForFunction(expected=>navigator.clipboard.readText().then(text=>text===expected),text);
    assert.equal(await owner.evaluate(()=>navigator.clipboard.readText()),text);
    await inert(owner);
  });
  await check('Denied clipboard access selects the complete repair text and explains the next action',async()=>{
    await owner.evaluate(()=>{window.n170OriginalClipboardWrite=navigator.clipboard.writeText;navigator.clipboard.writeText=async()=>{throw new DOMException('Synthetic denied clipboard permission','NotAllowedError');};});
    try{
      await owner.getByRole('button',{name:'Copy what needs fixing',exact:true}).click();
      await owner.getByText('Clipboard unavailable. Copy the selected text, or download it.',{exact:true}).waitFor();
      const box=owner.locator('#repair-prompt');assert.deepEqual(await box.evaluate(el=>[el.selectionStart,el.selectionEnd,document.activeElement===el]),[0,(await box.inputValue()).length,true]);
    }finally{await owner.evaluate(()=>{navigator.clipboard.writeText=window.n170OriginalClipboardWrite;delete window.n170OriginalClipboardWrite;});}
  });
  await owner.screenshot({path:path.join(out,'security-ease-repair-desktop.png'),fullPage:true});
  await check('Copying a repair prompt and owner confirmation cannot bypass missing evidence',async()=>{
    assert.equal(await owner.getByRole('button',{name:'Review calculation',exact:true}).isEnabled(),false);
    await owner.getByRole('checkbox',{name:/I reviewed the assistant/}).check();
    await owner.getByRole('button',{name:'Reconcile file',exact:true}).click();
    await owner.getByText('Assistant-reported source · review privately',{exact:true}).waitFor();
    assert.equal(await owner.getByRole('button',{name:'Review calculation',exact:true}).isEnabled(),false);
    assert.equal(await owner.getByRole('button',{name:'Correct row 1',exact:true}).isEnabled(),false);
    assert.equal(await owner.locator('tbody tr').count(),hostile.observations.length);
    await inert(owner);
  });
  await owner.setViewportSize({width:390,height:844});
  await check('Mobile repair prompt stays readable, selectable and within the page',async()=>{
    const prompt=owner.locator('#repair-prompt');await prompt.scrollIntoViewIfNeeded();
    assert.equal(await owner.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    assert(await prompt.evaluate(el=>parseFloat(getComputedStyle(el).fontSize)>=14));
    await prompt.focus();await owner.keyboard.press('ControlOrMeta+A');
    assert.deepEqual(await prompt.evaluate(el=>[document.activeElement===el,el.selectionStart,el.selectionEnd]),[true,0,(await prompt.inputValue()).length]);
    await inert(owner);
  });
  await owner.screenshot({path:path.join(out,'security-ease-repair-mobile.png'),fullPage:true});

  const invalidOwner=await makePage();
  const invalidHandoffs=[
    ['Duplicate and escaped duplicate handoff keys are rejected','{"currency":"USD",'+JSON.stringify(fixture).slice(1),/repeated field|duplicate/i],
    ['Escaped duplicate handoff keys cannot choose alternate values','{"\\u0063urrency":"USD",'+JSON.stringify(fixture).slice(1),/repeated field|duplicate/i],
    ['Prototype-shaped handoff fields are rejected without prototype pollution','{"__proto__":{"n170Polluted":"yes"},'+JSON.stringify(fixture).slice(1),/not part|unknown|schema/i],
  ];
  for(const [name,text,pattern]of invalidHandoffs)await check(name,async()=>{
    await invalidOwner.getByLabel('Or paste your AI’s reply',{exact:true}).fill(text);
    await invalidOwner.getByRole('button',{name:'Review my record',exact:true}).click();
    const alert=invalidOwner.getByRole('alert').first();await alert.waitFor();assert.match(await alert.innerText(),pattern);
    assert.equal(await invalidOwner.getByText('Assistant-reported source · review privately',{exact:true}).count(),0);
    assert.equal(await invalidOwner.getByLabel('Or paste your AI’s reply',{exact:true}).inputValue(),text);
    await inert(invalidOwner);
  });
  const oversizedOwner=await makePage();
  await check('Oversized assistant JSON is rejected without rendering or calculating it',async()=>{
    const text=JSON.stringify(fixture).padEnd(1000001,' ');
    await oversizedOwner.locator('input[type=file]').first().setInputFiles({name:'synthetic-oversize.json',mimeType:'application/json',buffer:Buffer.from(text)});
    const alert=oversizedOwner.getByRole('alert').first();await alert.waitFor();assert.match(await alert.innerText(),/1,000,000|1 MB|size/i);
    assert.equal(await oversizedOwner.getByText('Assistant-reported source · review privately',{exact:true}).count(),0);await inert(oversizedOwner);
  });

  // These invented observations are deliberately signed as self-reported. A key
  // holder can do this; successful verification must never authenticate the data.
  const invented=structuredClone(fixture);invented.synthetic=false;invented.observations.at(-1).nav='111.12345';
  const reviewed=await importStatement(JSON.stringify(invented),{currency:invented.currency,frequency:invented.frequency,flowTimingConfirmed:true});
  const key=await generateProfileKey();const signer=createSigner(key.privateKey,key.publicKey);
  const display='Synthetic <img src=https://invalid.test/p onerror=window.n170Injected=1>';
  const profile=await appendPerformanceStamp(await createProfile(display,signer),reviewed.normalizedCsv,invented.frequency,signer,{provenance:provenanceFromImport(reviewed,{accountScope:'Synthetic invented account',reviewed:true})});
  const profileText=JSON.stringify(profile);const safeEmbedded=profileText.replaceAll('<','\\u003c').replaceAll('>','\\u003e').replaceAll('&','\\u0026');
  const wrapper=`<!doctype html><title>Hostile wrapper must be ignored</title><script>window.n170Injected=1;fetch('https://invalid.test/script')</script><img src="https://invalid.test/image" onerror="window.n170Injected=1"><iframe src="https://invalid.test/frame"></iframe><div id="n170-injected">Unauthorized wrapper</div><script id="n170-evidence" type="application/json">${safeEmbedded}</script>`;
  const employer=await makePage();await employer.getByRole('button',{name:'Review a record',exact:true}).click();
  await check('Employer imports valid embedded evidence without rendering the hostile HTML wrapper',async()=>{
    await checkRecord(employer,wrapper,'synthetic-hostile-wrapper.html');await employer.getByRole('heading',{name:display,exact:true}).waitFor();
    assert(!await employer.locator('body').innerText().then(text=>text.includes('Unauthorized wrapper')));
    assert.equal(await employer.getByRole('heading',{name:display,exact:true}).locator('img').count(),0);await inert(employer);
  });
  await check('Valid signatures on invented observations leave source, identity, time and completeness unchecked',async()=>{
    const rail=await employer.locator('.evidence-rail').innerText();
    for(const claim of ['Reproduced from disclosed returns','Valid for this key','Self-reported · not authenticated','Not established','No independent evidence','Supplied observations only'])assert(rail.includes(claim));
    const body=await employer.locator('body').innerText();assert.match(body,/complete account coverage are not established/);assert.match(body,/No prior publication checked/);assert.match(body,/Self-reported performance/);
    assert.equal(profile.stamps[0].payload.source_kind,'self_reported');await inert(employer);
  });
  await employer.screenshot({path:path.join(out,'security-ease-employer-desktop.png'),fullPage:true});
  await check('A matching expected key still does not establish identity',async()=>{
    await employer.getByText('Add earlier evidence for comparison',{exact:true}).click();
    await employer.getByLabel('Expected key code (optional)',{exact:true}).fill(profileKeyCode(profile));
    await employer.getByRole('button',{name:'Check record',exact:true}).click();await employer.getByRole('heading',{name:display,exact:true}).waitFor();
    assert.match(await employer.locator('.evidence-rail').innerText(),/Expected key matches; identity unchecked/);
  });
  await check('Wrong expected key removes prior success and blocks verification',async()=>{
    await employer.getByLabel('Expected key code (optional)',{exact:true}).fill('0000-0000-0000-0000-0000');
    await employer.getByRole('button',{name:'Check record',exact:true}).click();const alert=employer.getByRole('alert').first();await alert.waitFor();assert.match(await alert.innerText(),/different key/);assert.equal(await employer.locator('.review-result').count(),0);
    await employer.getByLabel('Expected key code (optional)',{exact:true}).fill('');
  });
  const tampered=structuredClone(profile);tampered.stamps[0].payload.metrics.total_return_twr_e8++;
  await check('Tampered signed financial results are rejected',()=>expectRejectedRecord(employer,JSON.stringify(tampered),/integrity|metric|return/i));
  const otherKey=await generateProfileKey();const otherSigner=createSigner(otherKey.privateKey,otherKey.publicKey);
  const other=await appendPerformanceStamp(await createProfile('Synthetic other key',otherSigner),reviewed.normalizedCsv,invented.frequency,otherSigner);
  const wrongSignature=structuredClone(profile);wrongSignature.stamps[0].signature=other.stamps[0].signature;
  await check('A valid signature from another key cannot replace this record signature',()=>expectRejectedRecord(employer,JSON.stringify(wrongSignature),/signature/i));
  await check('Duplicate signed-record fields are rejected',()=>expectRejectedRecord(employer,'{"display_name":'+JSON.stringify(display)+','+profileText.slice(1),/duplicate|repeat/i));
  await check('Prototype-shaped signed-record fields are rejected without pollution',()=>expectRejectedRecord(employer,'{"__proto__":{"n170Polluted":"yes"},'+profileText.slice(1),/invalid|format|field|structure/i));
  await check('Oversized employer files are rejected before a result is shown',async()=>{
    await employer.locator('input[type=file]').first().setInputFiles({name:'synthetic-oversize.html',mimeType:'text/html',buffer:Buffer.alloc(2000001,32)});
    const alert=employer.getByRole('alert').first();await alert.waitFor();assert.match(await alert.innerText(),/smaller than 2 MB/);assert.equal(await employer.locator('.review-result').count(),0);await inert(employer);
  });
  const sharing=await makePage();
  await check('A signed synthetic workflow exposes reviewer instructions with exact visible clipboard contents',async()=>{
    await sharing.getByLabel('Or paste your AI’s reply',{exact:true}).fill(JSON.stringify(fixture));
    await sharing.getByRole('button',{name:'Review my record',exact:true}).click();
    await sharing.getByText('Assistant-reported source · review privately',{exact:true}).waitFor();
    await sharing.getByRole('checkbox',{name:/I reviewed the assistant/}).check();await sharing.getByRole('button',{name:'Reconcile file',exact:true}).click();
    await sharing.getByText(/Reconciliation complete/).waitFor();await sharing.getByRole('button',{name:'Review calculation',exact:true}).click();
    await sharing.getByLabel('Public profile alias',{exact:true}).fill('Synthetic recipient note test');await sharing.getByRole('button',{name:'Create profile',exact:true}).click();
    await sharing.getByText(/Profile created and saved/).waitFor();await sharing.getByRole('checkbox',{name:/I reviewed the calculation/}).check();
    await sharing.getByRole('button',{name:'Sign record & save',exact:true}).click();await sharing.getByRole('heading',{name:'Ready for a thoughtful review.',exact:true}).waitFor();
    await sharing.getByText('Include a short note for your reviewer',{exact:true}).click();
    const note=sharing.locator('#recipient-instructions');assert.equal(await note.getAttribute('readonly'),'');const visible=await note.inputValue();
    assert.match(visible,/source you already trust/);assert.match(visible,/Valid arithmetic and signatures do not authenticate a broker/);assert.match(visible,/Compare/);
    assert(!visible.includes('Synthetic recipient note test'));assert(!visible.includes(fixture.source.connector));
    await sharing.context().grantPermissions(['clipboard-read','clipboard-write']);await sharing.getByRole('button',{name:'Copy review instructions',exact:true}).click();
    await sharing.waitForFunction(expected=>navigator.clipboard.readText().then(text=>text===expected),visible);assert.equal(await sharing.evaluate(()=>navigator.clipboard.readText()),visible);await inert(sharing);
    await sharing.screenshot({path:path.join(out,'security-ease-recipient-note.png'),fullPage:true});
  });
  await check('No injected execution, unexpected external requests or browser errors',async()=>{assert.deepEqual(externalRequests,[]);assert.deepEqual(errors,[]);});
  await rm(path.join(out,'security-ease-failure.png'),{force:true});
}catch(error){
  if(currentPage)await currentPage.screenshot({path:path.join(out,'security-ease-failure.png'),fullPage:true}).catch(()=>{});
  throw error;
}finally{
  await writeFile(path.join(out,'security-ease-results.json'),JSON.stringify({date:new Date().toISOString(),browser:await browser.version(),engine:'Playwright Chromium (real browser)',url:BASE,viewports:['1440x1000','390x844'],browser_plugin:'Browser plugin not available; existing Playwright workflow used.',scope:'Bounded hostile-input and blocked-repair workflow checks against production. All observations, labels and keys are synthetic. These checks do not constitute a complete security audit or Safari/Firefox testing.',tests,errors,external_requests:externalRequests},null,2));
  await browser.close();
}
