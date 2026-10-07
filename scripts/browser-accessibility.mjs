import path from 'node:path';
import {fileURLToPath} from 'node:url';
const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const {chromium}=await import(process.env.PLAYWRIGHT_MODULE || 'playwright');
import {writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
const browser=await chromium.launch();const page=await browser.newPage({viewport:{width:1440,height:1000}});await page.goto((process.env.N170_PREVIEW_URL || 'http://127.0.0.1:4174/'));
const results=await page.evaluate(()=>{
 const rgb=c=>c.match(/[\d.]+/g)?.slice(0,3).map(Number);const L=arr=>arr.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((a,v,i)=>a+v*[.2126,.7152,.0722][i],0);
 const checks=[];for(const e of document.querySelectorAll('h1,h2,h3,p,label,button,a,dt,dd,summary,input,select')){
  if(!e.getClientRects().length||e.disabled||e.type==='file')continue;
  const s=getComputedStyle(e);let parent=e,bg='';while(parent){const c=getComputedStyle(parent).backgroundColor;if(c!=='rgba(0, 0, 0, 0)'&&c!=='transparent'){bg=c;break;}parent=parent.parentElement;}if(!bg)bg='rgb(248,249,246)';
  const fg=L(rgb(s.color)),back=L(rgb(bg));const ratio=(Math.max(fg,back)+.05)/(Math.min(fg,back)+.05);const large=parseFloat(s.fontSize)>=24||(parseFloat(s.fontSize)>=18.66&&Number(s.fontWeight)>=700);checks.push({text:(e.innerText||e.value||e.ariaLabel||e.tagName).slice(0,90),ratio:Number(ratio.toFixed(2)),required:large?3:4.5,pass:ratio>=(large?3:4.5)});
 }return checks;
});
assert.equal(results.filter(x=>!x.pass).length,0,JSON.stringify(results.filter(x=>!x.pass)));
await page.getByRole('button',{name:'Import a file',exact:true}).click();
await page.getByRole('button',{name:'Try a synthetic example',exact:true}).click();await page.getByRole('button',{name:'Reopen saved draft',exact:true}).click();const focus=[];for(let i=0;i<8;i++){await page.keyboard.press('Tab');focus.push(await page.evaluate(()=>({inside:!!document.activeElement.closest('dialog'),name:document.activeElement.innerText})));}assert(focus.every(x=>x.inside));await page.keyboard.press('Escape');assert.equal(await page.getByRole('dialog').count(),0);
await page.setViewportSize({width:720,height:500});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await page.screenshot({path:path.join(process.env.N170_EVIDENCE_DIR || path.join(ROOT,'docs/verification'),'07-narrow-reflow.png'),fullPage:true});
await writeFile(path.join(process.env.N170_EVIDENCE_DIR || path.join(ROOT,'docs/verification'),'accessibility-results.json'),JSON.stringify({browser:await browser.version(),checks:results,dialog_focus_trap:focus,escape_closes_dialog:true,narrow_reflow:'720 CSS pixels passed; this models 200% desktop layout, not browser zoom/assistive technology certification'},null,2));await browser.close();console.log('Passed rendered text contrast, modal focus trap/Escape, and narrow reflow.');
