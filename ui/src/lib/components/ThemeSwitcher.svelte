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
		aria-label="Light theme"
	>
		<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
			<circle cx="12" cy="12" r="5"/>
			<path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
		</svg>
	</button>
	<button
		class:active={current === 'dark'}
		onclick={() => handleChange('dark')}
		title="Dark theme"
		aria-label="Dark theme"
	>
		<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
			<path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
		</svg>
	</button>
	<button
		class:active={current === 'system'}
		onclick={() => handleChange('system')}
		title="System theme"
		aria-label="System theme"
	>
		<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
			<rect x="2" y="3" width="20" height="14" rx="2"/>
			<path d="M8 21h8M12 17v4"/>
		</svg>
	</button>
</div>

<style>
	.theme-switcher {
		display: flex;
		gap: 0;
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		overflow: hidden;
	}

	button {
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--color-bg);
		color: var(--color-text-muted);
		border: none;
		padding: 0.5rem;
		cursor: pointer;
		transition: all 0.15s ease;
		border-right: 1px solid var(--color-border);
	}

	button:last-child {
		border-right: none;
	}

	button svg {
		width: 16px;
		height: 16px;
	}

	button:hover {
		color: var(--color-text);
		background: var(--color-surface);
	}

	button.active {
		color: var(--color-primary);
		background: rgba(8, 145, 178, 0.1);
		background: color-mix(in srgb, var(--color-primary) 10%, transparent);
	}
</style>
