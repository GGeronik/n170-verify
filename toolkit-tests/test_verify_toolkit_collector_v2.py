"""Original acquisition boundary tests; no engine execution is claimed."""
import unittest,base64,hashlib,copy
from datetime import datetime,timezone
from verify_toolkit.accounting_collector import Collector,encode,compact
from verify_toolkit.run_contract_v2 import decode_bundle,verify_capture_binding
class CollectorValueTests(unittest.TestCase):
 def test_inherited_and_static_descriptor_restoration(self):
  class Parent:
   def inherited(self):return 'original'
  class Child(Parent):
   @staticmethod
   def own():return 'static'
  original=Child.__dict__['own']; patches=[]
  collector=object.__new__(Collector)
  collector._patch(Child,'inherited',lambda self:'observed',patches)
  collector._patch(Child,'own',staticmethod(lambda:'observed'),patches)
  self.assertEqual(Child().inherited(),'observed')
  self.assertEqual(Child.own(),'observed')
  collector._restore(patches)
  self.assertNotIn('inherited',Child.__dict__)
  self.assertIs(Child.__dict__['own'],original)
  self.assertEqual(Child().inherited(),'original')
 def test_binary64_roundtrip_and_signed_zero(self):
  for v in (0.1,-0.0,1e-8,1/512,3/512):
   e=encode(v);self.assertEqual(e['repr'],repr(v));self.assertEqual(float(e['repr']).hex(),e['hex'])
 def test_nonfinite_and_unsafe_integer(self):
  for v in (float('nan'),float('inf'),-float('inf'),2**53):
   with self.assertRaises(ValueError):encode(v)
 def test_ambiguous_mapping_and_unknown_object(self):
  with self.assertRaises(ValueError):encode({1:'a','1':'b'})
  with self.assertRaises(TypeError):encode(object())
 def test_depth_and_timestamp(self):
  deep=0
  for _ in range(26):deep=[deep]
  for v in (deep,datetime(2026,1,1)):
   with self.assertRaises(ValueError):encode(v)
  self.assertEqual(encode(datetime(2026,1,1,tzinfo=timezone.utc)),'2026-01-01T00:00:00Z')
 def test_transport_version_allowlist_and_duplicate(self):
  f={'worker-result.json':base64.b64encode(b'{}').decode(),'baseline-capture.json':base64.b64encode(b'{}').decode()}
  line=b'N170_RESULT_BUNDLE_V2:'+base64.b64encode(compact(f))+b'\n'
  self.assertEqual(set(decode_bundle(line)),set(f));self.assertIsNone(decode_bundle(line.replace(b'_V2:',b'_V1:')))
  with self.assertRaises(ValueError):decode_bundle(line+line)
  f['../escape']='e30='
  with self.assertRaises(ValueError):decode_bundle(b'N170_RESULT_BUNDLE_V2:'+base64.b64encode(compact(f)))

class CaptureBindingTests(unittest.TestCase):
 def setUp(self):
  self.request={'run_id':'a'*32,'attempt_id':'000','strategy':'Control'}
  self.request_raw=compact(self.request)
  self.inputs=[{'path':name,'size':1,'sha256':hashlib.sha256(name.encode()).hexdigest()}
   for name in ('accounting_collector.py','engine_worker.py','engine_worker_v1.py')]
  by_name={i['path']:i['sha256'] for i in self.inputs}
  self.capture={'schema':'n170.freqtrade-baseline-capture.v1',
   'binding':dict(self.request,request_sha256=hashlib.sha256(self.request_raw).hexdigest(),input_inventory=self.inputs,
    collector_sha256=by_name['accounting_collector.py'],worker_sha256=by_name['engine_worker.py'],
    helper_sha256=by_name['engine_worker_v1.py'],market_metadata_sha256=None,engine_revision=None,
    engine_source_sha256=None,engine_source_after_sha256=None),
   'capture':{'status':'FAILED','reason_codes':['BASELINE_NOT_COMPLETED']}}
  self.bind()
 def bind(self):
  self.raw=compact(self.capture)
  self.worker={'capture':{'schema':self.capture['schema'],'path':'baseline-capture.json','size':len(self.raw),
   'sha256':hashlib.sha256(self.raw).hexdigest(),'status':'FAILED','reason_codes':['BASELINE_NOT_COMPLETED']}}
 def verify(self):
  return verify_capture_binding(self.worker,self.raw,self.request,self.request_raw,self.inputs)
 def test_failed_capture_identity_is_bound_without_financial_claim(self):
  self.assertEqual(self.verify(),self.capture)
 def test_rehashed_capture_cannot_change_attempt_or_sources(self):
  for key,value in (('run_id','b'*32),('attempt_id','001'),('collector_sha256','0'*64)):
   old=self.capture['binding'][key]
   self.capture['binding'][key]=value;self.bind()
   with self.assertRaises(ValueError):self.verify()
   self.capture['binding'][key]=old
 def test_worker_descriptor_cannot_lie_about_bytes_or_state(self):
  original=copy.deepcopy(self.worker)
  for key,value in (('size',True),('size',len(self.raw)+1),('status','COMPLETE'),('reason_codes',[])):
   self.worker=copy.deepcopy(original);self.worker['capture'][key]=value
   with self.assertRaises(ValueError):self.verify()
 def test_missing_capture_requires_explicit_failed_null_descriptor(self):
  self.worker['capture'].update(size=None,sha256=None)
  self.assertIsNone(verify_capture_binding(self.worker,None,self.request,self.request_raw,self.inputs))
  self.worker['capture']['status']='COMPLETE'
  with self.assertRaises(ValueError):verify_capture_binding(self.worker,None,self.request,self.request_raw,self.inputs)
