<script lang="ts">
	interface Props {
		expanded: boolean;
		/** What the toggle reveals, named in its title and accessible name. */
		label?: string;
		ontoggle: () => void;
	}

	let { expanded, label = 'annotations', ontoggle }: Props = $props();
</script>

<button
	class="toggle-annotations"
	onclick={ontoggle}
	title="Toggle {label}"
	aria-label="Toggle {label}"
	aria-expanded={expanded}
>
	{expanded ? '[-]' : '[+]'}
</button>
