<script lang="ts">
	interface Props {
		message?: string;
	}

	let { message = 'Loading' }: Props = $props();
</script>

<div class="loading">{message}</div>
