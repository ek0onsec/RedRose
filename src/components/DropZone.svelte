<!-- src/components/DropZone.svelte -->
<script lang="ts">
  import { open } from '@tauri-apps/plugin-dialog';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { onMount } from 'svelte';
  import type { FileEntry } from '../lib/types';

  let {
    file = $bindable<FileEntry | null>(null),
    mode = 'encrypt'
  }: { file: FileEntry | null; mode: 'encrypt' | 'decrypt' } = $props();

  let isDragging = $state(false);

  async function setFile(path: string) {
    try {
      const info = await invoke<{ name: string; size: number; ext: string }>('get_file_info', { path });
      file = { path, name: info.name, size: info.size, ext: info.ext };
    } catch {
      file = { path, name: path.split(/[/\\]/).pop() ?? path, size: 0, ext: '' };
    }
  }

  async function handleClick() {
    const filters = mode === 'decrypt'
      ? [{ name: 'RedRose Files', extensions: ['rr'] }]
      : undefined;
    const selected = await open({ multiple: false, filters });
    if (typeof selected === 'string') await setFile(selected);
  }

  function handleRemove(e: MouseEvent) {
    e.stopPropagation();
    file = null;
  }

  function formatSize(bytes: number): string {
    if (bytes === 0) return '—';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function getIcon(ext: string): string {
    const map: Record<string, string> = {
      '.pdf': '📄', '.png': '🖼', '.jpg': '🖼', '.jpeg': '🖼',
      '.mp3': '🎵', '.mp4': '🎬', '.wav': '🎵', '.txt': '📝',
      '.rr': '🔒', '.zip': '📦', '.docx': '📄', '.xlsx': '📊',
    };
    return map[ext.toLowerCase()] ?? '⬡';
  }

  onMount(async () => {
    const unlisten = await listen<{ paths: string[] }>('tauri://drag-drop', async (event) => {
      isDragging = false;
      const paths = event.payload.paths;
      if (paths.length > 0) await setFile(paths[0]);
    });

    const unlistenOver = await listen('tauri://drag-over', () => { isDragging = true; });
    const unlistenLeave = await listen('tauri://drag-leave', () => { isDragging = false; });

    return () => { unlisten(); unlistenOver(); unlistenLeave(); };
  });
</script>

<div
  class="dropzone"
  class:has-file={file !== null}
  class:dragging={isDragging}
  role="button"
  tabindex="0"
  onclick={handleClick}
  onkeydown={(e) => e.key === 'Enter' && handleClick()}
>
  {#if file}
    <div class="file-info">
      <div class="file-icon">{getIcon(file.ext)}</div>
      <div class="file-meta">
        <div class="file-name">{file.name}</div>
        <div class="file-size">{formatSize(file.size)} · {file.ext || '?'}</div>
      </div>
      <button class="remove-btn" onclick={handleRemove} aria-label="Remove file">✕</button>
    </div>
  {:else}
    <div class="empty-state">
      <div class="drop-icon">⬡</div>
      <div class="drop-primary">Drop classified file</div>
      <div class="drop-secondary">or click to browse</div>
    </div>
  {/if}
</div>

<style>
  .dropzone {
    border: 1px dashed rgba(192, 57, 43, 0.45);
    border-radius: 6px;
    padding: 24px 20px;
    margin-bottom: 16px;
    cursor: pointer;
    transition: border-color 0.2s, background 0.2s, box-shadow 0.2s;
    position: relative;
    overflow: hidden;
    min-height: 88px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: rgba(192, 57, 43, 0.04);
  }

  .dropzone::before {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, var(--red-subtle) 0%, transparent 60%);
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.2s;
  }

  .dropzone:hover, .dropzone.dragging {
    border-color: rgba(192, 57, 43, 0.75);
    box-shadow: 0 0 16px rgba(192, 57, 43, 0.12), inset 0 0 20px rgba(192, 57, 43, 0.06);
  }
  .dropzone:hover::before, .dropzone.dragging::before { opacity: 1; }

  .dropzone.dragging {
    border-style: solid;
    box-shadow: 0 0 24px rgba(192, 57, 43, 0.25), inset 0 0 30px rgba(192, 57, 43, 0.1);
  }

  .dropzone.has-file {
    border-color: rgba(192, 57, 43, 0.45);
    background: var(--red-subtle);
  }

  .empty-state { text-align: center; }

  .drop-icon {
    font-size: 28px;
    margin-bottom: 10px;
    opacity: 1;
    animation: pulse-icon 3s ease-in-out infinite;
  }

  @keyframes pulse-icon {
    0%, 100% { opacity: 1;   transform: scale(1); }
    50%       { opacity: 1;  transform: scale(1.08); }
  }

  .drop-primary {
    color: var(--text-primary);
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 5px;
    opacity: 1;
  }
  .drop-secondary {
    color: var(--red);
    font-size: 9px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    opacity: 1;
  }

  .file-info { display: flex; align-items: center; gap: 12px; width: 100%; }

  .file-icon {
    width: 36px; height: 36px;
    background: rgba(192, 57, 43, 0.1);
    border: 1px solid rgba(192, 57, 43, 0.2);
    border-radius: 4px;
    display: flex; align-items: center; justify-content: center;
    font-size: 16px; flex-shrink: 0;
  }

  .file-meta { flex: 1; min-width: 0; }
  .file-name {
    color: var(--text-primary); font-size: 11px; letter-spacing: 1px; margin-bottom: 3px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .file-size { color: var(--red); font-size: 10px; letter-spacing: 1px; }

  .remove-btn {
    background: transparent; border: none;
    color: var(--text-secondary); font-size: 14px; cursor: pointer;
    padding: 4px 6px; border-radius: 3px; flex-shrink: 0;
    transition: color 0.15s;
  }
  .remove-btn:hover { color: var(--red); }
</style>
