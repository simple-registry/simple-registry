<script lang="ts">
	interface Props {
		message: string;
	}

	let { message }: Props = $props();
</script>

<div class="error">
	<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
		<circle cx="12" cy="12" r="10"/>
		<path d="M15 9l-6 6M9 9l6 6"/>
	</svg>
	<span>{message}</span>
</div>
