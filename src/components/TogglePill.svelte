<!-- src/components/TogglePill.svelte -->
<script lang="ts">
  type Mode = 'encrypt' | 'decrypt';
  let { mode = $bindable<Mode>('encrypt') }: { mode: Mode } = $props();
</script>

<div class="toggle-pill">
  <button
    class="option"
    class:active={mode === 'encrypt'}
    onclick={() => (mode = 'encrypt')}
  >
    Encrypt
  </button>
  <button
    class="option"
    class:active={mode === 'decrypt'}
    onclick={() => (mode = 'decrypt')}
  >
    Decrypt
  </button>
</div>

<style>
  .toggle-pill {
    display: flex;
    background: var(--bg-panel);
    border: 1px solid var(--border-dark);
    border-radius: 30px;
    padding: 4px;
    margin-bottom: 22px;
  }

  .option {
    flex: 1;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    font-family: var(--font-mono);
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 9px 0;
    border-radius: 24px;
    cursor: pointer;
    transition: background 0.2s, color 0.2s, box-shadow 0.2s;
  }

  .option.active {
    background: var(--red);
    color: #fff;
    box-shadow: 0 0 16px var(--red-glow);
  }
</style>
