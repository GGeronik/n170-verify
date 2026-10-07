#!/usr/bin/env python3
"""Independent 200-digit Decimal controls; imports no application implementation.

Outputs reproducible synthetic source cases, their quantized return series and
expected integer metrics. The financial controls cover the declared end-flow
convention, not source authenticity or economic completeness.
"""
import datetime as dt
import json
import random
from decimal import Decimal, localcontext, ROUND_HALF_UP, ROUND_HALF_DOWN

U = Decimal(100000000)

def nearest_integer(value):
    # Application format specifies nearest integer with ties toward +infinity.
    return int(value.to_integral_value(rounding=ROUND_HALF_UP if value >= 0 else ROUND_HALF_DOWN))

def csv(rows):
    return 'date,nav,external_flow\n' + '\n'.join(','.join(row) for row in rows)

def control(name, rows, frequency):
    raw_factors = [(Decimal(current[1]) - Decimal(current[2])) / Decimal(previous[1]) for previous, current in zip(rows, rows[1:])]
    return_units = [nearest_integer((factor - 1) * U) for factor in raw_factors]
    returns = [Decimal(value) / U for value in return_units]
    wealth = peak = Decimal(1)
    drawdown = Decimal(0)
    for value in returns:
        wealth *= 1 + value
        peak = max(peak, wealth)
        drawdown = min(drawdown, wealth / peak - 1)
    volatility = None
    # Generated annualization controls use consecutive calendar days; sparse
    # fixed controls are deliberately below the product's 20-interval policy.
    if len(returns) >= 20:
        assert frequency == 365
        assert all((dt.date.fromisoformat(b[0]) - dt.date.fromisoformat(a[0])).days == 1 for a, b in zip(rows, rows[1:]))
        mean = sum(returns) / len(returns)
        volatility = (sum((value - mean) ** 2 for value in returns) / (len(returns) - 1) * frequency).sqrt()
    raw_wealth = Decimal(1)
    for factor in raw_factors:
        raw_wealth *= factor
    return {
        'name': name, 'input': csv(rows), 'periods_per_year': frequency,
        'return_units': return_units,
        'expected_metrics': {'total_return_twr_e8': nearest_integer((wealth - 1) * U), 'annualized_volatility_e8': None if volatility is None else nearest_integer(volatility * U), 'max_drawdown_e8': nearest_integer(drawdown * U)},
        'exact_decimal_source_twr': str(raw_wealth - 1),
        'rounded_series_twr': str(wealth - 1),
    }

with localcontext() as context:
    context.prec = 200
    cases = [
        control('large_flow_cancellation', [['2025-01-01','0.1','0'],['2025-01-02','999999999999999.9','999999999999999.8']], 252),
        control('cent_cancellation', [['2025-01-01','0.01','0'],['2025-01-02','100000000000000.01','100000000000000']], 252),
        control('ordinary_path_divergence', [['2025-01-01','100','0'],['2025-01-02','10','0'],['2025-01-03','100','0']], 252),
        control('gain_then_loss_flows', [['2025-01-01','100','0'],['2025-01-02','160','50'],['2025-01-03','143','-1']], 252),
        control('bundled_sample', [['2025-01-02','100','0'],['2025-01-03','101','0'],['2025-01-06','112.02','10'],['2025-01-07','110.8998','0']], 252),
    ]
    rng = random.Random(17020260914)
    for case_index in range(100):
        nav = Decimal(rng.randint(10000, 100000))
        rows = [['2025-01-01', str(nav), '0']]
        for interval in range(20 + case_index % 20):
            flow = Decimal(rng.randint(-100, 100))
            factor = 1 + Decimal(rng.randint(-800, 900)) / 10000
            nav = (nav * factor + flow).quantize(Decimal('0.000001'))
            day = dt.date(2025, 1, 2) + dt.timedelta(days=interval)
            rows.append([day.isoformat(), str(nav), str(flow)])
        cases.append(control(f'seeded_source_case_{case_index:03}', rows, 365))
    print(json.dumps({'method': 'Independent Python Decimal, 200 digits, deterministic seed 17020260914; exact source arithmetic followed by specified e8 quantization', 'case_count': len(cases), 'cases': cases}, indent=2))
