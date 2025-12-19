<script lang="ts">
	import type { Platform } from '$lib/api';
	import { formatPlatform } from '$lib/utils';

	interface Props {
		platform?: Platform;
	}

	let { platform }: Props = $props();
</script>

{#if platform}
	<span class="platform">{formatPlatform(platform)}</span>
{:else}
	<span class="untagged">-</span>
{/if}
