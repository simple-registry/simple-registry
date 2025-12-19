<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchRevisions, fetchUploads, deleteManifest as apiDeleteManifest, cancelUpload as apiCancelUpload, type ManifestEntry, type UploadEntry } from '$lib/api';
	import { formatSize, formatTimeAgo, displayNamespace as displayNs, buildTree, getTagConfirm, repoUrl, manifestUrl, digestConfirmKey, tagConfirmKey, uploadConfirmKey, type TreeNode } from '$lib/utils';
	import LoadingState from '$lib/components/LoadingState.svelte';
	import ErrorState from '$lib/components/ErrorState.svelte';
	import Breadcrumb from '$lib/components/Breadcrumb.svelte';
	import Card from '$lib/components/Card.svelte';
	import DeleteButton from '$lib/components/DeleteButton.svelte';
	import TagList from '$lib/components/TagList.svelte';
	import PlatformBadge from '$lib/components/PlatformBadge.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	let manifests: ManifestEntry[] = $state([]);
	let tree: TreeNode[] = $state([]);
	let uploads: UploadEntry[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);
	let deleteConfirm: string | null = $state(null);
	let deleting = $state(false);

	$effect(() => {
		loadData(data.namespace);
	});

	async function loadData(namespace: string) {
		loading = true;
		error = null;
		const [revisionsResult, uploadsResult] = await Promise.all([
			fetchRevisions(namespace),
			fetchUploads(namespace)
		]);
		if (revisionsResult.error) {
			error = revisionsResult.error;
		} else if (revisionsResult.data) {
			manifests = revisionsResult.data.manifests ?? [];
			tree = buildTree(manifests);
		}
		if (uploadsResult.data) {
			uploads = uploadsResult.data.uploads ?? [];
		} else {
			uploads = [];
		}
		loading = false;
	}

	async function deleteManifest(reference: string) {
		deleting = true;
		error = null;
		const err = await apiDeleteManifest(data.namespace, reference);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			await loadData(data.namespace);
		}
		deleting = false;
	}

	async function deleteTag(tag: string) {
		deleting = true;
		error = null;
		const err = await apiDeleteManifest(data.namespace, tag);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			await loadData(data.namespace);
		}
		deleting = false;
	}

	async function cancelUpload(uuid: string) {
		deleting = true;
		error = null;
		const err = await apiCancelUpload(data.namespace, uuid);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			await loadData(data.namespace);
		}
		deleting = false;
	}

	function handleRowClick(event: MouseEvent, digest: string) {
		const target = event.target as HTMLElement;
		if (target.tagName === 'BUTTON' || target.closest('button')) {
			return;
		}
		goto(manifestUrl(data.repository, data.namespace, digest));
	}
</script>

<svelte:head>
	<title>{displayNs(data.namespace, data.repository)} // {data.repository} // {getRegistryName()}</title>
</svelte:head>

<Breadcrumb items={[
	{ label: 'repositories', href: `${base}/` },
	{ label: data.repository, href: repoUrl(data.repository) },
	{ label: displayNs(data.namespace, data.repository) }
]} />

{#if loading}
	<LoadingState />
{:else if error}
	<ErrorState message={error} />
{:else}
	{#if uploads.length > 0}
		<Card title="uploads in progress" count={uploads.length} variant="warning">
			<table>
				<thead>
					<tr>
						<th>uuid</th>
						<th>size</th>
						<th>started</th>
						<th class="col-medium">actions</th>
					</tr>
				</thead>
				<tbody>
					{#each uploads as upload}
						<tr>
							<td><code class="uuid">{upload.uuid}</code></td>
							<td>{formatSize(upload.size)}</td>
							<td>{formatTimeAgo(upload.started_at)}</td>
							<td>
								<DeleteButton
									label="cancel"
									isConfirming={deleteConfirm === uploadConfirmKey(upload.uuid)}
									disabled={deleting}
									onconfirm={() => cancelUpload(upload.uuid)}
									oncancel={() => deleteConfirm = null}
									onrequestconfirm={() => deleteConfirm = uploadConfirmKey(upload.uuid)}
								/>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</Card>
	{/if}

	<table>
		<thead>
			<tr>
				<th>digest</th>
				<th>tags / platform</th>
				<th class="col-wide">actions</th>
			</tr>
		</thead>
		<tbody>
			{#if tree.length === 0}
				<tr>
					<td colspan="3" class="empty">no manifests found</td>
				</tr>
			{:else}
			{#each tree as node}
				<tr class="root-row clickable" onclick={(e) => handleRowClick(e, node.manifest.digest)}>
					<td class:has-children={node.children.length > 0}>
						{#if node.children.length > 0}<span class="index-icon" title="Multi-platform index"></span>{/if}<code>{node.manifest.digest}</code>
					</td>
					<td>
						<TagList
							tags={node.manifest.tags}
							deleteConfirm={getTagConfirm(deleteConfirm)}
							disabled={deleting}
							ondelete={deleteTag}
							onconfirmchange={(tag) => deleteConfirm = tag ? tagConfirmKey(tag) : null}
						/>
					</td>
					<td>
						<DeleteButton
							isConfirming={deleteConfirm === digestConfirmKey(node.manifest.digest)}
							disabled={deleting}
							onconfirm={() => deleteManifest(node.manifest.digest)}
							oncancel={() => deleteConfirm = null}
							onrequestconfirm={() => deleteConfirm = digestConfirmKey(node.manifest.digest)}
						/>
					</td>
				</tr>
				{#each node.children as child, idx}
					<tr class="child-row clickable" onclick={(e) => handleRowClick(e, child.manifest.digest)}>
						<td class="tree-branch" class:has-next={idx !== node.children.length - 1}>
							<code>{child.manifest.digest}</code>
						</td>
						<td>
							<PlatformBadge platform={child.platform} />
						</td>
						<td>
							<DeleteButton
								isConfirming={deleteConfirm === digestConfirmKey(child.manifest.digest)}
								disabled={deleting}
								onconfirm={() => deleteManifest(child.manifest.digest)}
								oncancel={() => deleteConfirm = null}
								onrequestconfirm={() => deleteConfirm = digestConfirmKey(child.manifest.digest)}
							/>
						</td>
					</tr>
				{/each}
			{/each}
			{/if}
		</tbody>
	</table>
{/if}
