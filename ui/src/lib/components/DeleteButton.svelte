<script lang="ts">
	interface Props {
		label?: string;
		confirmLabel?: string;
		isConfirming: boolean;
		disabled?: boolean;
		onconfirm: () => void;
		oncancel: () => void;
		onrequestconfirm: () => void;
	}

	let {
		label = 'delete',
		confirmLabel = 'confirm',
		isConfirming,
		disabled = false,
		onconfirm,
		oncancel,
		onrequestconfirm
	}: Props = $props();
</script>

<div class="actions">
	{#if isConfirming}
		<button class="danger" onclick={onconfirm} {disabled}>
			{disabled ? '...' : confirmLabel}
		</button>
		<button onclick={oncancel}>cancel</button>
	{:else}
		<button class="danger" onclick={onrequestconfirm}>{label}</button>
	{/if}
</div>
