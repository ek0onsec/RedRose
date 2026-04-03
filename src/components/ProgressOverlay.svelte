<!-- src/components/ProgressOverlay.svelte -->
<script lang="ts">
  let {
    percent = 0,
    phase = '',
    onCancel = undefined
  }: { percent: number; phase: string; onCancel?: () => void } = $props();
</script>

<div class="overlay">
  <div class="overlay-header label">
    {#if percent < 92}
      Processing...
    {:else}
      Choose save location
    {/if}
  </div>

  <div class="bar-wrap">
    <div class="bar-fill" style="width: {percent}%"></div>
  </div>

  <div class="stats">
    <div class="stat">
      <div class="stat-value">{percent}%</div>
      <div class="stat-label label">Progress</div>
    </div>
  </div>

  <div class="phase-text label">{phase}</div>

  {#if onCancel && percent < 92}
    <button class="cancel-btn" onclick={onCancel}>// Cancel</button>
  {/if}
</div>

<style>
  .overlay {
    border: 1px solid var(--border-dark);
    border-radius: 6px;
    padding: 22px 18px;
    margin-bottom: 16px;
    min-height: 88px;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .overlay-header { color: var(--red); font-size: 10px; letter-spacing: 3px; }

  .bar-wrap {
    background: var(--bg-panel);
    border-radius: 2px;
    height: 2px;
    overflow: hidden;
  }

  .bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--red), #e74c3c);
    box-shadow: 0 0 8px var(--red-glow);
    border-radius: 2px;
    transition: width 0.3s ease;
  }

  .stats { display: flex; gap: 8px; }

  .stat {
    flex: 1;
    background: var(--bg-mid);
    border: 1px solid var(--border-dark);
    border-radius: 3px;
    padding: 8px;
    text-align: center;
  }

  .stat-value { color: var(--red); font-size: 18px; font-weight: bold; }
  .stat-label { margin-top: 2px; }

  .phase-text { color: var(--text-secondary); font-size: 9px; letter-spacing: 2px; }

  .cancel-btn {
    background: transparent;
    border: 1px solid var(--border-dark);
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 9px;
    letter-spacing: 2px;
    padding: 7px;
    border-radius: 3px;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s;
  }
  .cancel-btn:hover { color: var(--red); border-color: var(--red); }
</style>
