// src/lib/types.ts
export interface FileEntry {
  path: string;
  name: string;
  size: number;
  ext: string;
}

export interface ProgressUpdate {
  percent: number;
  phase: string;
}

export interface OperationResult {
  success: boolean;
  saved_path?: string;
  error?: string;
}
