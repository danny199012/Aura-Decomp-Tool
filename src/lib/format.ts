/** Small formatting helpers shared across views. */

export function hex32(v: number): string {
  return `0x${(v >>> 0).toString(16).toUpperCase().padStart(8, '0')}`;
}

export function hex64(v: number): string {
  return `0x${Number(v).toString(16).toUpperCase()}`;
}

export function fmtBytes(v: number): string {
  if (!v || v <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(v) / Math.log(1024)), units.length - 1);
  return `${(v / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

export function bytesToHex(bytes: number[]): string {
  return (bytes ?? []).map((b) => (b & 0xff).toString(16).padStart(2, '0').toUpperCase()).join(' ');
}

export function fmtSectionsize(size: number): string {
  return `${size.toLocaleString()} (${fmtBytes(size)})`;
}
