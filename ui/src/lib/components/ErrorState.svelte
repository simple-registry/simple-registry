<script lang="ts">
	interface Props {
		message: string;
	}

	let { message }: Props = $props();
</script>

<div class="error">{message}</div>
