"""Original bounded observer for the separately installed pinned Freqtrade baseline.

No upstream implementation is copied. Runtime hooks are disclosed and restored.
"""
from __future__ import annotations
import hashlib
import importlib.metadata
import json
import logging
import math
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
import platform
import sys

SCHEMA = 'n170.freqtrade-baseline-capture.v1'
POLICY = 'freqtrade-2026.8-full-baseline-observer.v1'
PRECISE_SHA256 = '445721221b65f37cc198adaeec26f68b214926e82ea2bfc0195a346ec94773ed'
MAX_CAPTURE = 2 * 1024 * 1024
MAX_RECORDS = 10000
SAFE_INT = 2**53 - 1
ORDER_FIELDS = ('id','order_id','pair','side','type','status','is_open','amount','filled','remaining','price','average','safe_price','cost','fee_base','created_at','filled_at','tag')
TRADE_FIELDS = ('trade_id','pair','is_open','is_short','trading_mode','leverage','amount','stake_amount','open_rate','close_rate','fee_open','fee_close','fee_open_cost','fee_close_cost','fee_open_currency','fee_close_currency','open_date','close_date','exit_reason','entry_count','exit_count','close_profit_abs','realized_profit','funding_fees','has_open_orders','orders')
COUNTERS = ('rejected_trades','timedout_entry_orders','timedout_exit_orders','canceled_trade_entries','canceled_entry_orders','replaced_entry_orders','canceled_exit_orders','replaced_exit_orders')


def compact(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def encode(value, depth=0, nodes=None):
    """Encode supported observed scalars without rounding or evaluating repr text."""
    if nodes is None: nodes=[0]
    nodes[0]+=1
    if depth>24 or nodes[0]>200000: raise ValueError('CAPTURE_STRUCTURE_LIMIT')
    def child(x): return encode(x,depth+1,nodes)
    if isinstance(value,Enum): return child(value.value)
    if type(value).__module__.split('.')[0]=='numpy':
        kind=type(value).__name__
        if kind=='float64': value=float(value)
        elif kind.startswith(('int','uint')) or kind=='bool': value=value.item()
        else: raise TypeError('UNSUPPORTED_NUMPY_SCALAR')
    if value is None or type(value) is bool: return value
    if type(value) is int:
        if abs(value)>SAFE_INT: raise ValueError('UNSAFE_INTEGER')
        return value
    if type(value) is float:
        if not math.isfinite(value): raise ValueError('NONFINITE_NATIVE')
        return {'encoding':'binary64','repr':repr(value),'hex':value.hex()}
    if type(value) is str:
        if len(value.encode('utf-8'))>1024*1024: raise ValueError('CAPTURE_STRING_LIMIT')
        return value
    if isinstance(value,datetime):
        if value.tzinfo is None: raise ValueError('NAIVE_DATETIME')
        return value.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    if isinstance(value,Path): return str(value)
    if type(value) in (list,tuple): return [child(x) for x in value]
    if type(value) is dict:
        result={}
        for key,item in value.items():
            if type(key) not in (str,int): raise TypeError('UNSUPPORTED_MAPPING_KEY')
            key=str(key)
            if key in result: raise ValueError('AMBIGUOUS_MAPPING_KEY')
            nodes[0]+=1
            result[key]=child(item)
        return result
    raise TypeError('UNSUPPORTED_NATIVE_TYPE:'+type(value).__name__)


def dataframe(frame):
    return {'columns':[str(c) for c in frame.columns], 'rows':[list(row) for row in frame.itertuples(index=False,name=None)]}


def order_record(order):
    return dict(zip(ORDER_FIELDS,(order.id,order.order_id,order.ft_pair,order.ft_order_side,order.order_type,
        order.status,order.ft_is_open,order.amount,order.filled,order.remaining,order.price,order.average,
        order.safe_price,order.cost,order.ft_fee_base,order.order_date_utc,order.order_filled_utc,order.ft_order_tag)))


def trade_record(trade):
    return dict(zip(TRADE_FIELDS,(trade.id,trade.pair,trade.is_open,trade.is_short,trade.trading_mode,trade.leverage,
        trade.amount,trade.stake_amount,trade.open_rate,trade.close_rate,trade.fee_open,trade.fee_close,
        trade.fee_open_cost,trade.fee_close_cost,trade.fee_open_currency,trade.fee_close_currency,
        trade.open_date_utc,trade.close_date_utc,trade.exit_reason,trade.nr_of_successful_entries,
        trade.nr_of_successful_exits,trade.close_profit_abs,trade.realized_profit,trade.funding_fees,
        trade.has_open_orders,[order_record(order) for order in trade.orders])))


def wallets(backtesting):
    wallet=backtesting.wallets
    return {'balances':[{'currency':key,'free':v.free,'used':v.used,'total':v.total}
                        for key,v in sorted(wallet.get_all_balances().items())],
            'cash':wallet.get_total('USDT'),'asset':wallet.get_total('BTC')}


def runtime_identity():
    import ccxt
    import numpy
    precise=Path(ccxt.__file__).parent/'base/precise.py'
    sha=hashlib.sha256(precise.read_bytes()).hexdigest()
    info={'radix':sys.float_info.radix,'mant_dig':sys.float_info.mant_dig,'max_exp':sys.float_info.max_exp,
          'min_exp':sys.float_info.min_exp,'rounds':sys.float_info.rounds}
    result={'implementation':platform.python_implementation(),'python_version':platform.python_version(),
            'float_info':info,'numpy_version':numpy.__version__,'ccxt_version':ccxt.__version__,
            'ccxt_precise_sha256':sha,'ccxt_precise_after_sha256':None}
    if (result['implementation']!='CPython' or result['python_version']!='3.14.7'
            or result['numpy_version']!='2.4.6' or result['ccxt_version']!='4.5.76'
            or info!={'radix':2,'mant_dig':53,'max_exp':1024,'min_exp':-1021,'rounds':1}
            or sha!=PRECISE_SHA256): raise ValueError('UNSUPPORTED_RUNTIME')
    return result,precise


class Collector:
    def __init__(self, request, request_raw, input_root):
        self.request=request; self.input=Path(input_root); self.active=False; self.forced=False
        self.failed=False; self.patches=[]; self.inner=[]; self.terminal_sources={}
        self.data={'schema':SCHEMA,'capture_policy':POLICY,
          'binding':{'run_id':request['run_id'],'attempt_id':request['attempt_id'],'strategy':request['strategy'],
            'request_sha256':hashlib.sha256(request_raw).hexdigest(),'input_inventory':request['input_inventory'],
            'collector_sha256':self._hash('accounting_collector.py'),'worker_sha256':self._hash('engine_worker.py'),
            'helper_sha256':self._hash('engine_worker_v1.py'),'market_metadata_sha256':None,
            'engine_revision':None,'engine_source_sha256':None,'engine_source_after_sha256':None},
          'capture':{'status':'INCOMPLETE','reason_codes':[],'hook_counts':{k:0 for k in ('baseline','backtest','opening','pre_force_exit','final')},
                     'completion_count':0,'closed_trade_count':0,'terminal_order_count':0,'truncated':False},
          'runtime':None,'scope':{'pair':'BTC/USDT','timeframe':'5m','trading_mode':'spot','fee_model':'quote-filled-price-rate.v1'},
          'window':{'requested_timerange':request['timerange'],'backtest_start':None,'backtest_end':None,'processed_bounds':{},'candle_count':len(json.loads((self.input/'data/BTC_USDT-5m.json').read_bytes()))},
          'resolved':None,'opening':None,'completions':[],'closes':[],'pre_force_exit':None,'final':None,
          'trust':{'execution':'local modeled backtest capture; recipient has not witnessed execution',
                   'authenticity':'unsigned; producer, broker and hardware identity not authenticated',
                   'completeness':'observed selected baseline only; global attempts unknown',
                   'fees':'rates observed; quote fees are a separately declared model, not broker receipts',
                   'observer':'original runtime wrappers call original methods once with unchanged arguments/results; source hashes do not prove unmodified process behavior'}}

    def _hash(self,name): return hashlib.sha256((self.input/name).read_bytes()).hexdigest()
    def _error(self,reason,truncated=False):
        self.failed=True; self.data['capture']['status']='FAILED'
        if reason not in self.data['capture']['reason_codes']: self.data['capture']['reason_codes'].append(reason)
        self.data['capture']['truncated'] |= truncated

    def _store(self,fn):
        if self.failed: return
        try:
            fn()
            if len(compact(self.data))>MAX_CAPTURE-65536:
                self._error('CAPTURE_BYTE_LIMIT',True)
        except Exception:
            logging.exception('Original accounting observer failed')
            self._error('CAPTURE_OBSERVER_ERROR')

    def _patch(self,owner,name,replacement,collection):
        # Preserve inherited lookup as well as descriptors owned by the class.
        owned=name in owner.__dict__
        original=owner.__dict__.get(name)
        setattr(owner,name,replacement); collection.append((owner,name,owned,original))

    @staticmethod
    def _restore(collection):
        while collection:
            owner,name,owned,original=collection.pop()
            if owned: setattr(owner,name,original)
            else: delattr(owner,name)

    def __enter__(self):
        from freqtrade.optimize.analysis.lookahead import LookaheadAnalysis
        self.data['runtime'],self.precise_path=runtime_identity()
        original=LookaheadAnalysis.fill_full_varholder
        collector=self
        def baseline(instance,*args,**kwargs):
            collector.data['capture']['hook_counts']['baseline']+=1
            if collector.data['capture']['hook_counts']['baseline']!=1:
                collector._error('MULTIPLE_BASELINES')
                return original(instance,*args,**kwargs)
            collector.active=True
            try:
                collector._install_inner()
                return original(instance,*args,**kwargs)
            finally:
                collector.active=False
                collector._restore(collector.inner)
        self._patch(LookaheadAnalysis,'fill_full_varholder',baseline,self.patches)
        return self

    def _install_inner(self):
        from freqtrade.optimize.backtesting import Backtesting, DATE_IDX, OPEN_IDX, HIGH_IDX, LOW_IDX, CLOSE_IDX
        from freqtrade.persistence import LocalTrade, Order
        collector=self
        original_backtest=Backtesting.backtest
        def backtest(bt,processed,start_date,end_date,*args,**kwargs):
            def before():
                collector.data['capture']['hook_counts']['backtest']+=1
                collector.data['window'].update(backtest_start=encode(start_date),backtest_end=encode(end_date))
                settings={k:getattr(bt.strategy,k) for k in ('timeframe','startup_candle_count','minimal_roi','stoploss','can_short','position_adjustment_enable','order_types')}
                collector.data['resolved']=encode({'config':bt.strategy.config,'strategy_settings':settings})
            collector._store(before)
            actual=original_backtest(bt,processed,start_date,end_date,*args,**kwargs)
            def after():
                collector.data['capture']['hook_counts']['final']+=1
                closed=list(LocalTrade.bt_trades)
                collector.data['final']=encode({'wallets':wallets(bt),'open_trades':[trade_record(t) for t in LocalTrade.bt_trades_open],
                    'closed_trades':[trade_record(t) for t in closed],'trade_rows':dataframe(actual['results']),
                    'native_final_balance':actual['final_balance'],'native_total_closed_profit':LocalTrade.bt_total_profit,
                    'close_order':[t.id for t in closed],'engine_counters':{k:getattr(bt,k) for k in COUNTERS},
                    'wallet_summary':dataframe(actual['wallet_summary'])})
                collector.data['capture']['closed_trade_count']=len(closed)
                collector.data['capture']['terminal_order_count']=sum(len(t.orders) for t in closed)
            collector._store(after)
            return actual
        self._patch(Backtesting,'backtest',backtest,self.inner)
        original_convert=Backtesting._get_ohlcv_as_lists
        def convert(bt,processed,*args,**kwargs):
            def observe():
                collector.data['capture']['hook_counts']['opening']+=1
                collector.data['opening']=encode({'wallets':wallets(bt),'starting_balance':bt.starting_balance,
                    'open_trades':[trade_record(t) for t in LocalTrade.bt_trades_open],
                    'closed_trade_count':len(LocalTrade.bt_trades),'total_closed_profit':LocalTrade.bt_total_profit})
                for pair,frame in processed.items():
                    if frame.empty: raise ValueError('EMPTY_PROCESSED_DATA')
                    collector.data['window']['processed_bounds'][pair]=encode({'first':frame.iloc[0]['date'],'last':frame.iloc[-1]['date'],'count':len(frame)})
                    collector.terminal_sources[pair]=encode({key:frame.iloc[-1][key] for key in ('date','open','high','low','close','volume')})
            collector._store(observe)
            return original_convert(bt,processed,*args,**kwargs)
        self._patch(Backtesting,'_get_ohlcv_as_lists',convert,self.inner)
        original_fill=Order.close_bt_order
        def fill(order,close_date,trade,*args,**kwargs):
            result=original_fill(order,close_date,trade,*args,**kwargs)
            def observe():
                if len(collector.data['completions'])>=MAX_RECORDS:
                    collector._error('CAPTURE_RECORD_LIMIT',True); return
                collector.data['completions'].append(encode({'sequence':len(collector.data['completions'])+1,
                    'phase':'forced_liquidation' if collector.forced else 'baseline','trade_id':trade.id,
                    'order':order_record(order),'trade_fee_rates':{'open':trade.fee_open,'close':trade.fee_close},
                    'trade_fee_costs':{'open':trade.fee_open_cost,'close':trade.fee_close_cost},
                    'trade_fee_currencies':{'open':trade.fee_open_currency,'close':trade.fee_close_currency}}))
                collector.data['capture']['completion_count']=len(collector.data['completions'])
            collector._store(observe)
            return result
        self._patch(Order,'close_bt_order',fill,self.inner)
        original_close=LocalTrade.close_bt_trade
        def close(trade):
            before=LocalTrade.bt_total_profit
            result=original_close(trade)
            def observe():
                if len(collector.data['closes'])>=MAX_RECORDS:
                    collector._error('CAPTURE_RECORD_LIMIT',True); return
                collector.data['closes'].append(encode({'sequence':len(collector.data['closes'])+1,'trade_id':trade.id,
                    'close_profit_abs':trade.close_profit_abs,'total_profit_before':before,'total_profit_after':LocalTrade.bt_total_profit}))
            collector._store(observe)
            return result
        self._patch(LocalTrade,'close_bt_trade',staticmethod(close),self.inner)
        original_terminal=Backtesting.handle_left_open
        def terminal(bt,open_trades,data,*args,**kwargs):
            def observe():
                collector.data['capture']['hook_counts']['pre_force_exit']+=1
                candles={}
                for pair,rows in data.items():
                    if not rows: raise ValueError('EMPTY_TERMINAL_ROWS')
                    row=rows[-1]
                    candles[pair]={'ohlcv':collector.terminal_sources[pair],
                                  'backtest_row':encode(dict(zip(('date','open','high','low','close'),(row[DATE_IDX],row[OPEN_IDX],row[HIGH_IDX],row[LOW_IDX],row[CLOSE_IDX]))))}
                collector.data['pre_force_exit']={'wallets':encode(wallets(bt)),
                    'open_trades':encode([trade_record(t) for trades in open_trades.values() for t in trades]),'terminal_candles':candles}
            collector._store(observe); collector.forced=True
            try: return original_terminal(bt,open_trades,data,*args,**kwargs)
            finally: collector.forced=False
        self._patch(Backtesting,'handle_left_open',terminal,self.inner)

    def __exit__(self,kind,exc,tb):
        self._restore(self.inner); self._restore(self.patches); self.active=False
        if kind is not None: self._error('BASELINE_OR_DETECTOR_FAILED')
        return False

    def finalize(self,worker,output):
        engine=worker.get('engine',{})
        self.data['binding'].update(engine_revision=engine.get('revision'),engine_source_sha256=engine.get('source_sha256'),
            engine_source_after_sha256=engine.get('source_after_sha256'),market_metadata_sha256=worker.get('offline_adapter',{}).get('market_metadata_sha256'))
        if self.data['runtime'] is not None:
            after=hashlib.sha256(self.precise_path.read_bytes()).hexdigest()
            self.data['runtime']['ccxt_precise_after_sha256']=after
            if after!=PRECISE_SHA256: self._error('CCXT_SOURCE_CHANGED')
        if (not self.failed and all(n==1 for n in self.data['capture']['hook_counts'].values())
                and worker.get('outcome') in ('COMPLETED','INSUFFICIENT')):
            self.data['capture']['status']='COMPLETE'
        elif not self.failed:
            self._error('BASELINE_NOT_COMPLETED')
        raw=compact(self.data)+b'\n'
        if len(raw)>MAX_CAPTURE:
            self._error('CAPTURE_BYTE_LIMIT',True)
            # Retain an explicit failed prefix, never a successful truncated capture.
            self.data['final']=None; self.data['resolved']=None
            raw=compact(self.data)+b'\n'
            if len(raw)>MAX_CAPTURE:
                self.data['completions']=[]; self.data['closes']=[]; raw=compact(self.data)+b'\n'
        path=Path(output)/'baseline-capture.json'
        with path.open('xb') as stream: stream.write(raw)
        return {'schema':SCHEMA,'path':path.name,'size':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
                'status':self.data['capture']['status'],'reason_codes':self.data['capture']['reason_codes']}
