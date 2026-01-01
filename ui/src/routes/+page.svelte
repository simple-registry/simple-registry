<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchRepositories, type RepositoryInfo } from '$lib/api';
	import { repoUrl } from '$lib/utils';
	import LoadingState from '$lib/components/LoadingState.svelte';
	import ErrorState from '$lib/components/ErrorState.svelte';
	import Breadcrumb from '$lib/components/Breadcrumb.svelte';

	let repositories: RepositoryInfo[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);

	onMount(async () => {
		const result = await fetchRepositories();
		if (result.error) {
			error = result.error;
		} else if (result.data) {
			repositories = result.data.repositories;
		}
		loading = false;
	});
</script>

<svelte:head>
	<title>{getRegistryName()} &gt; Repositories</title>
</svelte:head>

<Breadcrumb items={[{ label: 'Repositories', href: `${base}/` }]} />

{#if loading}
	<LoadingState message="Loading repositories" />
{:else if error}
	<ErrorState message={error} />
{:else}
	<table>
		<thead>
			<tr>
				<th>Name</th>
				<th>Features</th>
				<th class="col-medium">Namespaces</th>
			</tr>
		</thead>
		<tbody>
			{#if repositories.length === 0}
				<tr>
					<td colspan="3" class="empty">No repositories found</td>
				</tr>
			{:else}
				{#each repositories as repo}
					<tr class="clickable" onclick={() => goto(repoUrl(repo.name))}>
						<td>{repo.name}</td>
						<td>
							{#if repo.pull_through_cache}
								<span class="badge pull-through">Cache</span>
							{/if}
							{#if repo.immutable_tags}
								<span class="badge immutable">Immutable</span>
							{/if}
							{#if !repo.pull_through_cache && !repo.immutable_tags}
								<span class="no-features">-</span>
							{/if}
						</td>
						<td>{repo.namespace_count > 0 ? repo.namespace_count : '-'}</td>
					</tr>
				{/each}
			{/if}
		</tbody>
	</table>
{/if}
