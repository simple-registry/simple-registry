<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchRevisions, fetchUploads, deleteManifest as apiDeleteManifest, cancelUpload as apiCancelUpload, type UploadEntry } from '$lib/api';
	import { formatSize, formatTimeAgo, displayNamespace as displayNs, buildTree, getTagConfirm, repoUrl, manifestUrl, digestConfirmKey, tagConfirmKey, uploadConfirmKey, getAttestationType, type TreeNode } from '$lib/utils';
	import LoadingState from '$lib/components/LoadingState.svelte';
	import ErrorState from '$lib/components/ErrorState.svelte';
	import Breadcrumb from '$lib/components/Breadcrumb.svelte';
	import Card from '$lib/components/Card.svelte';
	import DeleteButton from '$lib/components/DeleteButton.svelte';
	import TagList from '$lib/components/TagList.svelte';
	import PlatformBadge from '$lib/components/PlatformBadge.svelte';
	import AttestationBadge from '$lib/components/AttestationBadge.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	let tree: TreeNode[] = $state([]);
	let uploads: UploadEntry[] = $state([]);
	let loading = $state(true);
	let error: string | null = $state(null);
	let deleteConfirm: string | null = $state(null);
	let deleting = $state(false);
	let expanded: Set<string> = $state(new Set());

	function toggleExpand(digest: string, event: MouseEvent) {
		event.stopPropagation();
		const newExpanded = new Set(expanded);
		if (newExpanded.has(digest)) {
			newExpanded.delete(digest);
		} else {
			newExpanded.add(digest);
		}
		expanded = newExpanded;
	}

	function hasChildren(node: TreeNode): boolean {
		return node.children.length > 0 || node.attestations.length > 0;
	}

	function hasReferrers(referrers: { digest: string }[] | undefined): boolean {
		return (referrers?.length ?? 0) > 0;
	}

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
			tree = buildTree(revisionsResult.data.manifests ?? []);
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
				{@const nodeHasChildren = hasChildren(node)}
				{@const nodeExpanded = expanded.has(node.manifest.digest)}
				<tr class="root-row clickable" onclick={(e) => handleRowClick(e, node.manifest.digest)}>
					<td class="has-children" class:expanded={nodeExpanded}>
						{#if nodeHasChildren}<button class="tree-toggle" onclick={(e) => toggleExpand(node.manifest.digest, e)}><span class="toggle-icon">{nodeExpanded ? '−' : '+'}</span></button>{:else}<span class="tree-toggle leaf"></span>{/if}<code>{node.manifest.digest}</code>
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
				{#if nodeExpanded}
				{#each node.children as child, idx}
					{@const childReferrers = child.manifest.referrers ?? []}
					{@const hasChildReferrers = hasReferrers(childReferrers)}
					{@const childExpanded = expanded.has(child.manifest.digest)}
					{@const isLast = idx === node.children.length - 1 && node.attestations.length === 0}
					<tr class="child-row clickable" onclick={(e) => handleRowClick(e, child.manifest.digest)}>
						<td class="tree-branch" class:has-next={!isLast} class:has-attestations={hasChildReferrers && childExpanded}>
							{#if hasChildReferrers}<button class="tree-toggle" onclick={(e) => toggleExpand(child.manifest.digest, e)}><span class="toggle-icon">{childExpanded ? '−' : '+'}</span></button>{#if childExpanded}<span class="branch-line"></span>{/if}{:else}<span class="tree-toggle leaf"></span>{/if}<code>{child.manifest.digest}</code>
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
					{#if childExpanded}
					{#each childReferrers as referrer, ridx}
						{@const isLastRef = ridx === childReferrers.length - 1}
						<tr class="child-row clickable" onclick={(e) => handleRowClick(e, referrer.digest)}>
							<td class="nested-tree-branch" class:has-next={!isLastRef}>
								{#if !isLast}<span class="parent-line"></span>{/if}<span class="tree-toggle leaf"></span><code>{referrer.digest}</code>
							</td>
							<td>
								<AttestationBadge type={getAttestationType(referrer)} />
							</td>
							<td>
								<DeleteButton
									isConfirming={deleteConfirm === digestConfirmKey(referrer.digest)}
									disabled={deleting}
									onconfirm={() => deleteManifest(referrer.digest)}
									oncancel={() => deleteConfirm = null}
									onrequestconfirm={() => deleteConfirm = digestConfirmKey(referrer.digest)}
								/>
							</td>
						</tr>
					{/each}
					{/if}
				{/each}
				{/if}
				{#if nodeExpanded}
				{#each node.attestations as att, idx}
					<tr class="child-row clickable" onclick={(e) => handleRowClick(e, att.digest)}>
						<td class="tree-branch" class:has-next={idx !== node.attestations.length - 1}>
							<span class="tree-toggle leaf"></span><code>{att.digest}</code>
						</td>
						<td>
							<AttestationBadge type={att.type} />
						</td>
						<td>
							<DeleteButton
								isConfirming={deleteConfirm === digestConfirmKey(att.digest)}
								disabled={deleting}
								onconfirm={() => deleteManifest(att.digest)}
								oncancel={() => deleteConfirm = null}
								onrequestconfirm={() => deleteConfirm = digestConfirmKey(att.digest)}
							/>
						</td>
					</tr>
				{/each}
				{/if}
			{/each}
			{/if}
		</tbody>
	</table>
{/if}
