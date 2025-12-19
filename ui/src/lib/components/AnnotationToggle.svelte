<script lang="ts">
	interface Props {
		expanded: boolean;
		ontoggle: () => void;
	}

	let { expanded, ontoggle }: Props = $props();
</script>

<button class="toggle-annotations" onclick={ontoggle} title="Toggle annotations">
	{expanded ? '[-]' : '[+]'}
</button>
