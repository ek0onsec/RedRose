<!-- src/App.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { listen } from '@tauri-apps/api/event';
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import TogglePill from './components/TogglePill.svelte';
  import DropZone from './components/DropZone.svelte';
  import PasswordInput from './components/PasswordInput.svelte';
  import ProgressOverlay from './components/ProgressOverlay.svelte';
  import StatusLine from './components/StatusLine.svelte';
  import { encryptFile, decryptFile } from './lib/tauri';
  import type { FileEntry, ProgressUpdate } from './lib/types';

  type AppStatus = 'idle' | 'ready' | 'processing' | 'success' | 'error';

  let mode       = $state<'encrypt' | 'decrypt'>('encrypt');
  let file       = $state<FileEntry | null>(null);
  let password   = $state('');
  let status     = $state<AppStatus>('idle');
  let statusMsg  = $state('Awaiting file');
  let progress   = $state(0);
  let progPhase  = $state('');

  let dotState = $derived(
    status === 'processing' ? 'processing'
    : status === 'error'    ? 'error'
    : (status === 'ready' || status === 'success') ? 'ready'
    : 'idle'
  );

  let canExecute = $derived(
    file !== null && password.length >= 1 && status !== 'processing'
  );

  let btnLabel = $derived(
    status === 'processing' ? 'Processing...'
    : mode === 'encrypt'    ? 'Execute — Encrypt'
    : 'Execute — Decrypt'
  );

  $effect(() => {
    if (status === 'processing' || status === 'success' || status === 'error') return;
    if (file === null) {
      status = 'idle';
      statusMsg = 'Awaiting file';
    } else if (password.length === 0) {
      status = 'idle';
      statusMsg = 'Enter passphrase';
    } else {
      status = 'ready';
      statusMsg = 'Ready — XChaCha20-Poly1305 + RedRose Layer';
    }
  });

  async function handleExecute() {
    if (!file || !canExecute) return;

    status = 'processing';
    progress = 0;
    progPhase = 'Initializing...';

    try {
      const result = mode === 'encrypt'
        ? await encryptFile(file.path, password)
        : await decryptFile(file.path, password);

      if (result.success) {
        status = 'success';
        statusMsg = 'Done — file saved';
        setTimeout(reset, 3000);
      } else if (result.error === 'Cancelled') {
        status = 'ready';
        statusMsg = 'Cancelled';
      } else {
        status = 'error';
        statusMsg = result.error ?? '// OPERATION FAILED';
      }
    } catch (e: unknown) {
      status = 'error';
      const msg = e instanceof Error ? e.message : String(e);
      statusMsg = msg.includes('AUTHENTICATION') ? '// AUTHENTICATION FAILED'
        : msg.includes('FORMAT')  ? '// INVALID FORMAT — NOT A REDROSE FILE'
        : msg.includes('CORRUPT') ? '// CORRUPTED FILE'
        : '// ERROR';
    }
  }

  function reset() {
    file = null;
    password = '';
    status = 'idle';
    statusMsg = 'Awaiting file';
    progress = 0;
    progPhase = '';
  }

  async function handleClose()    { await getCurrentWindow().close(); }
  async function handleMinimize() { await getCurrentWindow().minimize(); }
  async function handleMaximize() {
    const win = getCurrentWindow();
    if (await win.isMaximized()) { await win.unmaximize(); }
    else                         { await win.maximize(); }
  }

  onMount(async () => {
    const unlisten = await listen<ProgressUpdate>('rr-progress', (event) => {
      progress = event.payload.percent;
      progPhase = event.payload.phase;
    });
    return unlisten;
  });
</script>

<div class="app-window">
  <!-- Titlebar -->
  <div class="titlebar" data-tauri-drag-region>
    <div class="titlebar-dots">
      <button class="dot red"    onclick={handleClose}    aria-label="Close"></button>
      <button class="dot yellow" onclick={handleMinimize} aria-label="Minimize"></button>
      <button class="dot green"  onclick={handleMaximize} aria-label="Maximize"></button>
    </div>
    <div class="titlebar-name">RedRose — Cipher Unit</div>
  </div>

  <!-- Body -->
  <div class="app-body">
    <TogglePill bind:mode />

    {#if status === 'processing'}
      <ProgressOverlay percent={progress} phase={progPhase} />
    {:else}
      <DropZone bind:file {mode} />
    {/if}

    <PasswordInput bind:value={password} disabled={file === null || status === 'processing'} />

    <button
      class="btn-execute"
      disabled={!canExecute}
      onclick={handleExecute}
    >
      {btnLabel}
    </button>

    <StatusLine dotState={dotState as 'idle' | 'ready' | 'processing' | 'error'} message={statusMsg} />
  </div>
</div>

<style>
  .app-window {
    height: 100vh;
    width: 100vw;
    background: var(--bg-deep);
    border: 1px solid var(--border-dark);
    display: flex;
    flex-direction: column;
    border-radius: 10px;
    overflow: hidden;
  }

  /* Titlebar */
  .titlebar {
    background: var(--bg-mid);
    border-bottom: 1px solid var(--border-mid);
    padding: 12px 16px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
    cursor: default;
  }

  .titlebar-dots { display: flex; gap: 6px; align-items: center; }

  .dot {
    width: 11px; height: 11px;
    border-radius: 50%;
    background: #1e1e26;
    border: none;
    cursor: default;
    padding: 0;
    display: block;
  }

  .dot.red    { background: var(--red);    box-shadow: 0 0 6px var(--red-glow); cursor: pointer; transition: opacity 0.15s; }
  .dot.yellow { background: #f5a623;       cursor: pointer; transition: opacity 0.15s; }
  .dot.green  { background: #27ae60;       cursor: pointer; transition: opacity 0.15s; }
  .dot.red:hover, .dot.yellow:hover, .dot.green:hover { opacity: 0.75; }

  .titlebar-name {
    margin-left: auto;
    color: var(--red);
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    opacity: 0.7;
    pointer-events: none;
  }

  /* Body */
  .app-body {
    flex: 1;
    padding: 22px 22px 18px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  /* Execute button */
  .btn-execute {
    width: 100%;
    background: var(--red);
    border: none;
    border-radius: 4px;
    padding: 13px;
    color: #fff;
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 4px;
    text-transform: uppercase;
    cursor: pointer;
    margin-bottom: 0;
    box-shadow: 0 0 24px var(--red-glow);
    transition: box-shadow 0.2s, opacity 0.2s;
    position: relative;
    overflow: hidden;
  }

  .btn-execute::after {
    content: '';
    position: absolute;
    top: 0; left: -120%;
    width: 60%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255,255,255,0.07), transparent);
    transform: skewX(-20deg);
    transition: left 0.5s ease;
  }
  .btn-execute:hover::after { left: 120%; }
  .btn-execute:hover { box-shadow: 0 0 36px var(--red-glow); }
  .btn-execute:disabled {
    opacity: 0.25;
    cursor: not-allowed;
    box-shadow: none;
  }
</style>
