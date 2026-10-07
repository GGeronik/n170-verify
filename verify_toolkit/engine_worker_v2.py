"""Original versioned acquisition entrypoint; v1 helper and upstream stay unchanged."""
from __future__ import annotations
import base64
import json
import logging
from pathlib import Path
import traceback

import engine_worker_v1 as boundary
from accounting_collector import Collector


def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(name)s %(message)s')
    receipt={'schema':'n170.freqtrade-worker.v2','outcome':'FAILED'}
    collector=None
    try:
        raw=(boundary.INPUT/'request.json').read_bytes()
        request=json.loads(raw)
        if request.get('schema')!='n170.freqtrade-request.v2': raise ValueError('V2_REQUEST_REQUIRED')
        collector=Collector(request,raw,boundary.INPUT)
        with collector:
            boundary.run(receipt)
    except BaseException as exc:
        receipt['outcome']='FAILED'
        receipt['error']={'type':type(exc).__name__,'message':str(exc)}
        traceback.print_exc()
    finally:
        if collector is not None:
            try:
                import freqtrade
                after=boundary.digest(boundary.canonical(boundary.inventory(Path(freqtrade.__file__).parent,python_only=True)))
                if after!=boundary.ENGINE_SOURCE_SHA256:
                    collector._error('ENGINE_CHANGED'); receipt['outcome']='FAILED'
                if 'engine' in receipt: receipt['engine']['source_after_sha256']=after
                inputs=[x for x in boundary.inventory(boundary.INPUT) if x['path']!='request.json']
                if inputs!=collector.request['input_inventory']:
                    collector._error('INPUT_CHANGED'); receipt['outcome']='FAILED'
                receipt['capture']=collector.finalize(receipt,boundary.OUTPUT)
            except BaseException as exc:
                receipt['outcome']='FAILED'; receipt['capture']={'schema':'n170.freqtrade-baseline-capture.v1',
                    'path':'baseline-capture.json','size':None,'sha256':None,'status':'FAILED','reason_codes':['CAPTURE_FINALIZATION_FAILED']}
                traceback.print_exc()
    boundary.write_json(boundary.OUTPUT/'worker-result.json',receipt)
    files={}
    allowed={'worker-result.json','lookahead.csv','effective-config.json','market-metadata.json','baseline-capture.json'}
    total=0
    for path in sorted(boundary.OUTPUT.iterdir()):
        if path.name not in allowed or path.is_symlink() or not path.is_file(): raise ValueError('UNEXPECTED_OUTPUT')
        raw=path.read_bytes(); total+=len(raw)
        if len(raw)>2*1024*1024 or total>3*1024*1024: raise ValueError('OUTPUT_LIMIT')
        files[path.name]=base64.b64encode(raw).decode('ascii')
    encoded=base64.b64encode(boundary.canonical(files)).decode('ascii')
    if len(encoded)>6*1024*1024: raise ValueError('TRANSPORT_LIMIT')
    print('N170_RESULT_BUNDLE_V2:'+encoded,flush=True)
    return 0 if receipt['outcome']!='FAILED' else 1


if __name__=='__main__': raise SystemExit(main())
