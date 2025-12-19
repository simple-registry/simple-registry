<script lang="ts">
	import { onMount } from 'svelte';
	import { initTheme, setTheme, getThemePreference, type ThemePreference } from '$lib/theme.svelte';

	let current: ThemePreference = $state('system');

	onMount(() => {
		initTheme();
		current = getThemePreference();
	});

	function handleChange(newTheme: ThemePreference) {
		current = newTheme;
		setTheme(newTheme);
	}
</script>

<div class="theme-switcher">
	<button
		class:active={current === 'light'}
		onclick={() => handleChange('light')}
		title="Light theme"
	>light</button>
	<button
		class:active={current === 'dark'}
		onclick={() => handleChange('dark')}
		title="Dark theme"
	>dark</button>
	<button
		class:active={current === 'system'}
		onclick={() => handleChange('system')}
		title="System theme"
	>system</button>
</div>

<style>
	.theme-switcher {
		display: flex;
		gap: 0.25rem;
	}

	button {
		background: transparent;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
		padding: 0.15rem 0.4rem;
		font-size: 10px;
		cursor: pointer;
		transition: all 0.15s;
	}

	button:hover {
		color: var(--color-text);
		border-color: var(--color-text-muted);
	}

	button.active {
		color: var(--color-primary);
		border-color: var(--color-primary);
	}
</style>
