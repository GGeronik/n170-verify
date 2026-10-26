// W. J. Cody's three-region SPECFUN CALERF approximation (March 1990).
// Coefficients and evaluation order: https://netlib.org/specfun/erf
const A = [
  3.16112374387056560e0, 1.13864154151050156e2,
  3.77485237685302021e2, 3.20937758913846947e3,
  1.85777706184603153e-1,
];
const B = [
  2.36012909523441209e1, 2.44024637934444173e2,
  1.28261652607737228e3, 2.84423683343917062e3,
];
const C = [
  5.64188496988670089e-1, 8.88314979438837594e0,
  6.61191906371416295e1, 2.98635138197400131e2,
  8.81952221241769090e2, 1.71204761263407058e3,
  2.05107837782607147e3, 1.23033935479799725e3,
  2.15311535474403846e-8,
];
const D = [
  1.57449261107098347e1, 1.17693950891312499e2,
  5.37181101862009858e2, 1.62138957456669019e3,
  3.29079923573345963e3, 4.36261909014324716e3,
  3.43936767414372164e3, 1.23033935480374942e3,
];
const P = [
  3.05326634961232344e-1, 3.60344899949804439e-1,
  1.25781726111229246e-1, 1.60837851487422766e-2,
  6.58749161529837803e-4, 1.63153871373020978e-2,
];
const Q = [
  2.56852019228982242e0, 1.87295284992346047e0,
  5.27905102951428412e-1, 6.05183413124413191e-2,
  2.33520497626869185e-3,
];
const INV_SQRT_PI = 5.6418958354775628695e-1;

function splitExponential(y, scaledErfc) {
  const high = Math.trunc(y * 16) / 16;
  const low = (y - high) * (y + high);
  return (Math.exp(-high * high) * Math.exp(-low)) * scaledErfc;
}

export function erfc(x) {
  if (typeof x !== 'number' || Number.isNaN(x)) return NaN;
  const y = Math.abs(x);
  let result;
  if (y <= 0.46875) {
    const square = y > 1.11e-16 ? y * y : 0;
    let numerator = A[4] * square;
    let denominator = square;
    for (let i = 0; i < 3; i += 1) {
      numerator = (numerator + A[i]) * square;
      denominator = (denominator + B[i]) * square;
    }
    result = 1 - (y * (numerator + A[3])) / (denominator + B[3]);
  } else if (y <= 4) {
    let numerator = C[8] * y;
    let denominator = y;
    for (let i = 0; i < 7; i += 1) {
      numerator = (numerator + C[i]) * y;
      denominator = (denominator + D[i]) * y;
    }
    result = splitExponential(y, (numerator + C[7]) / (denominator + D[7]));
  } else if (y < 28) {
    const reciprocalSquare = 1 / (y * y);
    let numerator = P[5] * reciprocalSquare;
    let denominator = reciprocalSquare;
    for (let i = 0; i < 4; i += 1) {
      numerator = (numerator + P[i]) * reciprocalSquare;
      denominator = (denominator + Q[i]) * reciprocalSquare;
    }
    const correction = (reciprocalSquare * (numerator + P[4])) / (denominator + Q[4]);
    result = splitExponential(y, (INV_SQRT_PI - correction) / y);
  } else {
    // erfc(28) is below half the smallest binary64 subnormal; this also
    // handles infinity without forming Infinity - Infinity in the split.
    result = 0;
  }
  return x < 0 ? 2 - result : result;
}

export function normalCdf(z) {
  return z < 0 ? 0.5 * erfc(-z / Math.SQRT2) : 1 - 0.5 * erfc(z / Math.SQRT2);
}
