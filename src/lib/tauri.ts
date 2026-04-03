// src/lib/tauri.ts
import { invoke } from '@tauri-apps/api/core';
import type { OperationResult } from './types';

export async function encryptFile(filePath: string, password: string): Promise<OperationResult> {
  return invoke<OperationResult>('encrypt_file', { filePath, password });
}

export async function decryptFile(filePath: string, password: string): Promise<OperationResult> {
  return invoke<OperationResult>('decrypt_file', { filePath, password });
}
