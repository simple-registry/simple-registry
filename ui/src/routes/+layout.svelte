<script lang="ts">
	import '../app.css';
	import { base } from '$app/paths';
	import { onMount } from 'svelte';
	import ThemeSwitcher from '$lib/components/ThemeSwitcher.svelte';
	import { loadConfig, getRegistryName } from '$lib/config.svelte';

	let { children } = $props();
	let registryName = $state('simple-registry');

	onMount(async () => {
		await loadConfig();
		registryName = getRegistryName();
	});
</script>

<header>
	<div class="container header-content">
		<div class="header-left">
			<h1>{registryName}</h1>
			<nav>
				<a href="{base}/">[repositories]</a>
			</nav>
		</div>
		<ThemeSwitcher />
	</div>
</header>

<main class="container">
	{@render children()}
</main>
