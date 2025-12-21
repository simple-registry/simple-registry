<script lang="ts">
	import type { AttestationType } from '$lib/utils';

	interface Props {
		type: AttestationType;
	}

	let { type }: Props = $props();

	const labels: Record<AttestationType, string> = {
		slsa: 'SLSA',
		sbom: 'SBOM',
		signature: 'sig',
		artifact: 'artifact',
	};
</script>

<span class="attestation attestation-{type}">{labels[type]}</span>
