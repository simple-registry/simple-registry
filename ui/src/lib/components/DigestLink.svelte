<script lang="ts">
	import AnnotationToggle from './AnnotationToggle.svelte';

	interface Props {
		digest: string;
		href?: string;
		annotations?: Record<string, string>;
		expanded?: boolean;
		ontoggle?: () => void;
	}

	let { digest, href, annotations, expanded = false, ontoggle }: Props = $props();
</script>

{#if href}
	<a {href}><code>{digest}</code></a>
{:else}
	<code>{digest}</code>
{/if}
{#if annotations && ontoggle}
	<AnnotationToggle {expanded} {ontoggle} />
{/if}
