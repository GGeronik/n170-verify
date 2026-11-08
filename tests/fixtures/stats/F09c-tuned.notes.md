# F09c-tuned

Synthetic statistics fixture; derived, unsigned, never a headline.

Construction: Integer common-shift search at Pearson's bound. Seed: none (deterministic).

Start with F09c. Compute the quadratic minimiser S=2*skew/(excess_kurtosis+2); centre=round((S*sample_sd-mean)*1e8)=41565. Exhaust all integer shifts in [41465,41665], evaluate the complete oracle, retain lowest positive finite V. Winning common shift=41565, V=4.873879078104437e-14. Nonpositive candidates are recorded as refusals; no clamp, no change to the method.

The stored e8 integers are authoritative. Design targets are construction goals, not expectations. Expectations come exclusively from the independent stdlib oracle using SPEC-03 E1–E15. The integers use round-to-nearest, ties-to-even.
