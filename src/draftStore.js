// Explicit local drafts contain private source data; separate from signed records.
const DATABASE = 'n170-verify-drafts';
function open() {
  return new Promise((resolve, reject) => {
    let request;
    try { request = indexedDB.open(DATABASE, 1); } catch { reject(new Error('Local draft storage is unavailable. Export a private draft to keep your work.')); return; }
    request.onupgradeneeded = () => request.result.createObjectStore('drafts');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Local draft storage is unavailable. Export a private draft to keep your work.'));
    request.onblocked = () => reject(new Error('Draft storage is busy. Close other Verify tabs and retry, or export your draft.'));
  });
}
async function transaction(mode, run) {
  const db = await open();
  return new Promise((resolve, reject) => {
    let value; let error;
    let tx;
    try { tx = db.transaction('drafts', mode); }
    catch {
      db.close();
      reject(new Error('Draft storage could not start. Your work remains here; export a private draft and try again.'));
      return;
    }
    tx.oncomplete = () => { db.close(); resolve(value); };
    tx.onabort = () => { db.close(); reject(error || new Error('The draft could not be saved. Your work remains here; export a private draft.')); };
    try { run(tx.objectStore('drafts'), result => { value = result; }, message => { error = new Error(message); tx.abort(); }); }
    catch {
      error = new Error('The draft could not be saved. Your work remains here; export a private draft.');
      try { tx.abort(); } catch { db.close(); reject(error); }
    }
  });
}
export async function readDraft() {
  return transaction('readonly', (store, finish) => { const request = store.get('workspace'); request.onsuccess = () => finish(request.result || null); });
}
export async function saveDraft(data, expectedRevision = 0) {
  return transaction('readwrite', (store, finish, fail) => {
    const request = store.get('workspace');
    request.onsuccess = () => {
      if ((request.result?.revision || 0) !== expectedRevision) { fail('Another tab saved a newer draft. Export this draft before reopening the saved copy.'); return; }
      const next = { revision: expectedRevision + 1, data, savedAt: new Date().toISOString() };
      store.put(next, 'workspace'); finish(next);
    };
  });
}
