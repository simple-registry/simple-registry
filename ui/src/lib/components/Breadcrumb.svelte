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

<nav class="breadcrumb" aria-label="Breadcrumb">
	<ol>
		{#each items as item, i}
			<li>
				{#if i > 0}
					<svg class="separator" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
						<path d="M9 18l6-6-6-6"/>
					</svg>
				{/if}
				{#if item.href}
					<a href={item.href}>{item.label}</a>
				{:else}
					<span class="current">{item.label}</span>
				{/if}
			</li>
		{/each}
	</ol>
</nav>

<style>
	.breadcrumb {
		margin-bottom: 1.5rem;
	}

	ol {
		display: flex;
		align-items: center;
		list-style: none;
		margin: 0;
		padding: 0;
		gap: 0.25rem;
	}

	li {
		display: flex;
		align-items: center;
		gap: 0.25rem;
	}

	a, .current {
		display: inline-block;
		font-size: 0.8125rem;
		font-weight: 500;
		line-height: 1;
		padding: 0;
		margin: 0;
	}

	a {
		color: var(--color-text-muted);
		text-decoration: none;
		transition: color 0.15s ease;
	}

	a:hover {
		color: var(--color-primary);
		text-decoration: none;
	}

	.current {
		color: var(--color-text);
		font-weight: 600;
	}

	.separator {
		width: 14px;
		height: 14px;
		flex-shrink: 0;
		color: var(--color-text-muted);
	}
</style>
