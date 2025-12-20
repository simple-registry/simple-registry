<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchNamespaces, type NamespaceInfo } from '$lib/api';
	import { displayNamespace, namespaceUrl } from '$lib/utils';
	import LoadingState from '$lib/components/LoadingState.svelte';
	import ErrorState from '$lib/components/ErrorState.svelte';
	import Breadcrumb from '$lib/components/Breadcrumb.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	let namespaces: NamespaceInfo[] = $state([]);
	let pullThroughCache = $state(false);
	let upstreamUrls: string[] = $state([]);
	let immutableTags = $state(false);
	let immutableTagsExclusions: string[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	$effect(() => {
		loadData(data.repository);
	});

	async function loadData(repository: string) {
		loading = true;
		error = null;
		const result = await fetchNamespaces(repository);
		if (result.error) {
			error = result.error;
		} else if (result.data) {
			namespaces = result.data.namespaces;
			pullThroughCache = result.data.pull_through_cache;
			upstreamUrls = result.data.upstream_urls;
			immutableTags = result.data.immutable_tags;
			immutableTagsExclusions = result.data.immutable_tags_exclusions;
		}
		loading = false;
	}
</script>

<svelte:head>
	<title>{data.repository} // {getRegistryName()}</title>
</svelte:head>

<Breadcrumb items={[
	{ label: 'repositories', href: `${base}/` },
	{ label: data.repository }
]} />

{#if loading}
	<LoadingState message="loading namespaces" />
{:else if error}
	<ErrorState message={error} />
{:else}
	{#if pullThroughCache || immutableTags}
		<div class="config-panel">
			{#if pullThroughCache}
				<div class="config-item">
					<span class="config-label">upstream</span>
					<span class="config-value">{upstreamUrls.join(', ')}</span>
				</div>
			{/if}
			{#if immutableTags}
				<div class="config-item">
					<span class="config-label">immutable tags</span>
					{#if immutableTagsExclusions.length > 0}
						<span class="config-value">except: {immutableTagsExclusions.join(', ')}</span>
					{:else}
						<span class="config-value enabled">enabled</span>
					{/if}
				</div>
			{/if}
		</div>
	{/if}

	<table>
		<thead>
			<tr>
				<th>namespace</th>
				<th class="col-medium">manifests</th>
				<th class="col-medium">uploads</th>
			</tr>
		</thead>
		<tbody>
			{#if namespaces.length === 0}
				<tr>
					<td colspan="3" class="empty">no namespaces found</td>
				</tr>
			{:else}
				{#each namespaces as namespace}
					<tr class="clickable" onclick={() => goto(namespaceUrl(data.repository, displayNamespace(namespace.name, data.repository)))}>
						<td>{displayNamespace(namespace.name, data.repository)}</td>
						<td>{namespace.manifest_count > 0 ? namespace.manifest_count : '-'}</td>
						<td>{namespace.upload_count > 0 ? namespace.upload_count : '-'}</td>
					</tr>
				{/each}
			{/if}
		</tbody>
	</table>
{/if}
