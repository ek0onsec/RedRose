<!-- src/components/StatusLine.svelte -->
<script lang="ts">
  type DotState = 'idle' | 'ready' | 'processing' | 'error';

  let {
    dotState = 'idle',
    message = 'Awaiting file',
    version = 'v2.0.0'
  }: { dotState?: DotState; message?: string; version?: string } = $props();
</script>

<div class="status-line">
  <div
    class="dot"
    class:idle={dotState === 'idle'}
    class:ready={dotState === 'ready'}
    class:processing={dotState === 'processing'}
    class:error={dotState === 'error'}
  ></div>
  <span
    class="message"
    class:active={dotState !== 'idle'}
    class:error={dotState === 'error'}
  >{message}</span>
  <span class="version">{version}</span>
</div>

<style>
  .status-line {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 14px;
    border-top: 1px solid var(--border-mid);
  }

  .dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
    transition: background 0.3s, box-shadow 0.3s;
  }
  .dot.idle       { background: #1e1e26; }
  .dot.ready      { background: var(--green); box-shadow: 0 0 6px var(--green-glow); }
  .dot.processing { background: var(--red); box-shadow: 0 0 6px var(--red-glow); animation: pulse 1s infinite; }
  .dot.error      { background: #e74c3c; }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50%       { opacity: 0.4; }
  }

  .message {
    font-size: 9px; letter-spacing: 2px;
    color: var(--text-secondary);
    transition: color 0.3s;
    flex: 1;
  }
  .message.active { color: var(--green); }
  .message.error  { color: #e74c3c; }

  .version { color: #1c1c1c; font-size: 9px; letter-spacing: 1px; flex-shrink: 0; }
</style>
