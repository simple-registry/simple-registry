<script lang="ts">
	interface Props {
		tags: string[];
		deleteConfirm?: string | null;
		disabled?: boolean;
		ondelete?: (tag: string) => void;
		onconfirmchange?: (value: string | null) => void;
		getHref?: (tag: string) => string;
	}

	let {
		tags,
		deleteConfirm = null,
		disabled = false,
		ondelete,
		onconfirmchange,
		getHref
	}: Props = $props();

	let canDelete = $derived(ondelete !== undefined);
</script>

{#if tags.length > 0}
	{#each tags as tag}
		{#if canDelete}
			<span class="tag-with-delete">
				{#if getHref}
					<a class="tag" href={getHref(tag)}>{tag}</a>
				{:else}
					<span class="tag">{tag}</span>
				{/if}
				{#if deleteConfirm === tag}
					<button class="tag-delete danger" onclick={() => ondelete?.(tag)} {disabled} title="Confirm delete tag">✓</button>
					<button class="tag-delete" onclick={() => onconfirmchange?.(null)} title="Cancel">✗</button>
				{:else}
					<button class="tag-delete" onclick={() => onconfirmchange?.(tag)} title="Delete tag {tag}">×</button>
				{/if}
			</span>
		{:else if getHref}
			<a class="tag-standalone" href={getHref(tag)}>{tag}</a>
		{:else}
			<span class="tag-standalone">{tag}</span>
		{/if}
	{/each}
{:else}
	<span class="untagged">untagged</span>
{/if}
