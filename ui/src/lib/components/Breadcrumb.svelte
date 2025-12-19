<script lang="ts">
	interface BreadcrumbItem {
		label: string;
		href?: string;
	}

	interface Props {
		items: BreadcrumbItem[];
	}

	let { items }: Props = $props();
</script>

<h2>
	{#each items as item, i}
		{#if i > 0}
			<span class="separator">/</span>
		{/if}
		{#if item.href}
			<a href={item.href}>{item.label}</a>
		{:else}
			<span>{item.label}</span>
		{/if}
	{/each}
</h2>

<style>
	.separator {
		color: var(--color-text-muted);
	}
</style>
