<script lang="ts">
	interface Props {
		message?: string;
	}

	let { message = 'loading' }: Props = $props();
</script>

<div class="loading">{message}</div>
