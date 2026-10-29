// Our own shield-on-circuit-plinth artwork, rendered per instance so each copy
// can take a verdict colour (CSP forbids inline style attributes, so no CSS vars in SVG).
const TONES = {
  blue:  ['#8EC0FF', '#1D3FD8', '#3B6BFF'],
  red:   ['#FF9AA8', '#C8102E', '#FF3355'],
  amber: ['#FFD98A', '#C76A00', '#F59E0B'],
  green: ['#86F2C0', '#07925A', '#19C37D'],
  grey:  ['#CBD2EE', '#4F5A95', '#7F8BC4'],
};
const GLYPHS = {
  lock: s2 => `<path d="M104 104v-12a16 16 0 0 1 32 0v12" fill="none" stroke="#fff" stroke-width="8" stroke-linecap="round"/>
    <rect x="94" y="102" width="52" height="42" rx="9" fill="#fff"/><circle cx="120" cy="120" r="6" fill="${s2}"/><rect x="117" y="122" width="6" height="12" rx="3" fill="${s2}"/>`,
  alert: () => `<rect x="112" y="78" width="16" height="50" rx="8" fill="#fff"/><circle cx="120" cy="146" r="9" fill="#fff"/>`,
  check: () => `<path d="M94 116l18 18 36-38" fill="none" stroke="#fff" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>`,
  question: () => `<path d="M104 98a16 16 0 1 1 22 15c-4 2-6 5-6 9v6" fill="none" stroke="#fff" stroke-width="10" stroke-linecap="round"/><circle cx="120" cy="146" r="7" fill="#fff"/>`,
};
let n = 0;

export function shieldSVG(tone = 'blue', glyph = 'lock', simple = false) {
  const [s1, s2, glow] = TONES[tone] || TONES.blue;
  const id = `sh${++n}`;
  const shieldPath = 'M120 34l58 22v50c0 40-25 68-58 84-33-16-58-44-58-84V56z';
  const circuits = simple ? '' : `
    <g fill="none" stroke="${glow}" stroke-opacity=".75" stroke-width="1.6" stroke-linecap="round">
      <path d="M62 92H34V70H14"/><path d="M60 118H22"/><path d="M64 142H40v22H20"/>
      <path d="M178 92h28V70h20"/><path d="M180 118h38"/><path d="M176 142h24v22h20"/>
      <path d="M96 40V18H80"/><path d="M144 40V14h18"/><path d="M120 34V8"/>
    </g>
    <g fill="${glow}">
      <circle cx="14" cy="70" r="3"/><circle cx="22" cy="118" r="3"/><circle cx="20" cy="164" r="3"/>
      <circle cx="226" cy="70" r="3"/><circle cx="218" cy="118" r="3"/><circle cx="220" cy="164" r="3"/>
      <circle cx="80" cy="18" r="3"/><circle cx="162" cy="14" r="3"/><circle cx="120" cy="8" r="3"/>
    </g>
    <path d="M52 196l68 30 68-30-68-28z" fill="url(#${id}p)"/>
    <path d="M52 196v10l68 30v-10z" fill="${s2}" opacity=".95"/>
    <path d="M188 196v10l-68 30v-10z" fill="${s2}" opacity=".7"/>
    <path d="M52 196l68 30 68-30" fill="none" stroke="#fff" stroke-opacity=".55" stroke-width="1.2"/>`;
  return `<svg viewBox="${simple ? '50 28 140 170' : '0 0 240 240'}" aria-hidden="true" focusable="false">
    <defs>
      <linearGradient id="${id}s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${s1}"/><stop offset="1" stop-color="${s2}"/></linearGradient>
      <linearGradient id="${id}r" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#fff" stop-opacity=".95"/><stop offset=".5" stop-color="#fff" stop-opacity=".2"/><stop offset="1" stop-color="#fff" stop-opacity=".7"/></linearGradient>
      <radialGradient id="${id}g" cx=".5" cy=".5" r=".5"><stop offset="0" stop-color="${glow}" stop-opacity=".5"/><stop offset="1" stop-color="${glow}" stop-opacity="0"/></radialGradient>
      <linearGradient id="${id}p" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${s1}"/><stop offset="1" stop-color="${s2}"/></linearGradient>
    </defs>
    ${simple ? '' : `<circle cx="120" cy="112" r="112" fill="url(#${id}g)"/>`}
    ${circuits}
    <path d="${shieldPath}" fill="url(#${id}s)"/>
    <path d="${shieldPath}" fill="none" stroke="url(#${id}r)" stroke-width="3"/>
    <path d="M120 50l44 17v39c0 31-19 53-44 66-25-13-44-35-44-66V67z" fill="none" stroke="#fff" stroke-opacity=".35" stroke-width="1.5"/>
    <path d="M120 34l58 22v14L120 48z" fill="#fff" opacity=".18"/>
    ${(GLYPHS[glyph] || GLYPHS.lock)(s2)}
  </svg>`;
}

export function paintShield(el, tone, glyph) {
  el.innerHTML = shieldSVG(tone || el.dataset.tone, glyph || el.dataset.glyph, el.dataset.simple === '1');
}
