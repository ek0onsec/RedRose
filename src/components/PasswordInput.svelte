<!-- src/components/PasswordInput.svelte -->
<script lang="ts">
  let {
    value = $bindable(''),
    disabled = false
  }: { value: string; disabled?: boolean } = $props();

  let visible = $state(false);

  function strengthScore(pw: string): number {
    if (pw.length === 0) return 0;
    let score = 0;
    if (pw.length >= 8)  score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    return score;
  }

  function segmentColor(score: number): string {
    if (score <= 1) return 'weak';
    if (score <= 3) return 'medium';
    return 'strong';
  }

  let score = $derived(strengthScore(value));
  let colorClass = $derived(segmentColor(score));
</script>

<div class="field-group" class:disabled>
  <div class="field-label label">// Passphrase</div>
  <div class="field-wrapper">
    <input
      type={visible ? 'text' : 'password'}
      class="field-input"
      bind:value
      {disabled}
      placeholder="enter passphrase"
      autocomplete="off"
      spellcheck="false"
    />
    <button
      class="toggle-visible"
      type="button"
      onclick={() => (visible = !visible)}
      {disabled}
      aria-label={visible ? 'Hide passphrase' : 'Show passphrase'}
    >
      {visible ? '○' : '●'}
    </button>
  </div>
  <div class="strength-bar" aria-label="Password strength">
    {#each Array(5) as _, i}
      <div
        class="seg"
        class:filled={i < score}
        class:weak={i < score && colorClass === 'weak'}
        class:medium={i < score && colorClass === 'medium'}
        class:strong={i < score && colorClass === 'strong'}
      ></div>
    {/each}
  </div>
</div>

<style>
  .field-group { margin-bottom: 16px; }
  .field-group.disabled { opacity: 0.35; pointer-events: none; }
  .field-label { margin-bottom: 7px; }

  .field-wrapper { position: relative; }

  .field-input {
    width: 100%;
    background: var(--bg-field);
    border: 1px solid var(--border-dark);
    border-radius: 4px;
    padding: 11px 40px 11px 14px;
    color: var(--red);
    font-family: var(--font-mono);
    font-size: 15px;
    letter-spacing: 4px;
    outline: none;
    transition: border-color 0.2s;
  }

  .field-input:focus { border-color: rgba(192, 57, 43, 0.4); }
  .field-input::placeholder { color: var(--text-muted); letter-spacing: 2px; font-size: 10px; }

  .toggle-visible {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: none;
    color: var(--text-secondary);
    cursor: pointer;
    font-size: 11px;
    padding: 4px;
    line-height: 1;
  }
  .toggle-visible:hover { color: var(--red); }

  .strength-bar { display: flex; gap: 3px; margin-top: 6px; }

  .seg {
    height: 2px;
    flex: 1;
    background: var(--border-dark);
    border-radius: 2px;
    transition: background 0.25s;
  }

  .seg.filled.weak   { background: var(--red); }
  .seg.filled.medium { background: #e67e22; }
  .seg.filled.strong { background: var(--green); }
</style>
