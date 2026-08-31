import { createContext, useContext } from 'react';
import type { BinarySummary } from './tauri';

export interface FileContextValue {
  summary: BinarySummary | null;
  loadPath: (path: string) => Promise<BinarySummary>;
  error: string | null;
  clear: () => void;
}

export const FileContext = createContext<FileContextValue | null>(null);

export function useFile(): FileContextValue {
  const ctx = useContext(FileContext);
  if (!ctx) throw new Error('useFile must be used within FileProvider');
  return ctx;
}
