<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchRevisions, fetchUploads, fetchManifest, deleteManifest as apiDeleteManifest, cancelUpload as apiCancelUpload, blobUrl, type UploadEntry, type ParentRef, type Manifest, type ReferrerInfo } from '$lib/api';
	import { displayNamespace as displayNs, buildTree, buildTreeRows, repoUrl, namespaceUrl, manifestUrl, type TreeRowNode } from '$lib/utils';
	import LoadingState from '$lib/components/LoadingState.svelte';
	import ErrorState from '$lib/components/ErrorState.svelte';
	import Breadcrumb from '$lib/components/Breadcrumb.svelte';
	import ManifestView from '$lib/components/ManifestView.svelte';
	import RepositoryTree from '$lib/components/RepositoryTree.svelte';
	import type { PathParams } from './+page';

	let { data }: { data: PathParams } = $props();

	const isManifestView = $derived(data.reference !== null);
	const fullNamespace = $derived(`${data.repository}/${data.namespace}`);

	let rows: TreeRowNode[] = $state([]);
	let uploads: UploadEntry[] = $state([]);
	let selectedUploads: Set<string> = $state(new Set());

	let manifest: Manifest | null = $state(null);
	let digest: string | null = $state(null);
	let tags: string[] = $state([]);
	let referencedBy: ParentRef[] = $state([]);
	let childReferrers: Map<string, ReferrerInfo[]> = $state(new Map());

	let loading = $state(true);
	let error: string | null = $state(null);
	// Failures of an action taken on the current view, shown as a banner so the
	// view itself survives; `error` stays reserved for a load that produced no
	// view at all.
	let actionError: string | null = $state(null);
	let deleteConfirm: string | null = $state(null);
	let deleting = $state(false);
	let expanded: Set<string> = $state(new Set());

	// Monotonic token: each load claims the next value, so a slow response from
	// a superseded load is discarded instead of overwriting the current view.
	let loadToken = 0;

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

	$effect(() => {
		actionError = null;
		if (data.reference !== null) {
			loadManifest(fullNamespace, data.reference);
		} else {
			loadNamespace(fullNamespace);
		}
	});

	async function loadNamespace(namespace: string) {
		const token = ++loadToken;
		loading = true;
		error = null;
		const [revisionsResult, uploadsResult] = await Promise.all([
			fetchRevisions(namespace),
			fetchUploads(namespace)
		]);
		if (token !== loadToken) return;
		if (revisionsResult.error) {
			error = revisionsResult.error;
		} else if (revisionsResult.data) {
			rows = buildTreeRows(buildTree(revisionsResult.data.manifests ?? []));
		}
		uploads = uploadsResult.data?.uploads ?? [];
		if (uploadsResult.error) {
			actionError = `Could not list uploads (${uploadsResult.error}).`;
		}
		selectedUploads = new Set();
		loading = false;
	}

	async function loadManifest(namespace: string, reference: string) {
		const token = ++loadToken;
		loading = true;
		error = null;
		tags = [];
		referencedBy = [];
		childReferrers = new Map();

		const result = await fetchManifest(namespace, reference);
		if (token !== loadToken) return;
		if (result.error) {
			error = result.error;
			loading = false;
			return;
		}

		manifest = result.manifest;
		digest = result.digest;

		if (digest) {
			const revisionsResult = await fetchRevisions(namespace);
			if (token !== loadToken) return;
			if (revisionsResult.data) {
				const entry = revisionsResult.data.manifests.find(m => m.digest === digest);
				if (entry) {
					tags = entry.tags;
					referencedBy = entry.parents ?? [];
				}
				const newChildReferrers = new Map<string, ReferrerInfo[]>();
				for (const m of revisionsResult.data.manifests) {
					if (m.referrers && m.referrers.length > 0) {
						newChildReferrers.set(m.digest, m.referrers);
					}
				}
				childReferrers = newChildReferrers;
			}
		}
		loading = false;
	}

	// Refresh the view a delete was taken from. Reloading by a reference that
	// was just deleted would 404 and strand the user on an error page although
	// the delete succeeded, so leave for the digest when it still resolves and
	// for the namespace otherwise.
	async function reloadAfterDelete(deletedReference: string) {
		if (data.reference === null) {
			await loadNamespace(fullNamespace);
		} else if (data.reference !== deletedReference) {
			await loadManifest(fullNamespace, data.reference);
		} else if (digest && digest !== deletedReference) {
			await goto(manifestUrl(data.repository, data.namespace, digest));
		} else {
			await goto(namespaceUrl(data.repository, data.namespace));
		}
	}

	async function deleteByReference(reference: string) {
		deleting = true;
		actionError = null;
		const err = await apiDeleteManifest(fullNamespace, reference);
		if (err) {
			actionError = `Delete failed (${err}).`;
		} else {
			deleteConfirm = null;
			await reloadAfterDelete(reference);
		}
		deleting = false;
	}

	async function deleteByHash() {
		if (!digest) return;
		deleting = true;
		actionError = null;
		const err = await apiDeleteManifest(fullNamespace, digest);
		if (err) {
			actionError = `Delete failed (${err}).`;
			deleting = false;
		} else {
			window.location.href = namespaceUrl(data.repository, data.namespace);
		}
	}

	async function cancelUpload(uuid: string) {
		deleting = true;
		actionError = null;
		const err = await apiCancelUpload(fullNamespace, uuid);
		if (err) {
			actionError = `Cancel failed (${err}).`;
		} else {
			deleteConfirm = null;
			await loadNamespace(fullNamespace);
		}
		deleting = false;
	}

	async function cancelSelectedUploads() {
		deleting = true;
		actionError = null;
		const uuids = [...selectedUploads];
		const results = await Promise.all(
			uuids.map((uuid) => apiCancelUpload(fullNamespace, uuid))
		);
		deleteConfirm = null;
		await loadNamespace(fullNamespace);
		const failed = results.filter((err) => err !== null).length;
		if (failed > 0) {
			actionError = `Failed to cancel ${failed} of ${uuids.length} uploads.`;
		}
		deleting = false;
	}
</script>

<svelte:head>
	{#if isManifestView}
		<title>{getRegistryName()} &gt; {data.repository} &gt; {displayNs(data.namespace, data.repository)} &gt; {data.reference}</title>
	{:else}
		<title>{getRegistryName()} &gt; {data.repository} &gt; {displayNs(data.namespace, data.repository)}</title>
	{/if}
</svelte:head>

{#if isManifestView}
	<Breadcrumb items={[
		{ label: 'Repositories', href: `${base}/` },
		{ label: data.repository, href: repoUrl(data.repository) },
		{ label: displayNs(data.namespace, data.repository), href: namespaceUrl(data.repository, data.namespace) },
		{ label: data.reference ?? '' }
	]} />
{:else}
	<Breadcrumb items={[
		{ label: 'Repositories', href: `${base}/` },
		{ label: data.repository, href: repoUrl(data.repository) },
		{ label: displayNs(data.namespace, data.repository) }
	]} />
{/if}

{#if actionError}
	<div class="action-error">{actionError}</div>
{/if}

{#if loading}
	<LoadingState message={isManifestView ? 'Loading manifest' : 'Loading'} />
{:else if error}
	<ErrorState message={error} />
{:else if isManifestView && manifest}
	<ManifestView
		repository={data.repository}
		namespace={data.namespace}
		{manifest}
		{digest}
		{tags}
		{referencedBy}
		{childReferrers}
		{deleteConfirm}
		{deleting}
		ondeletetag={deleteByReference}
		ondeletebyhash={deleteByHash}
		onconfirmchange={(value) => deleteConfirm = value}
		getbloburl={(blobDigest) => blobUrl(fullNamespace, blobDigest)}
	/>
{:else}
	<RepositoryTree
		repository={data.repository}
		namespace={data.namespace}
		{rows}
		{uploads}
		{selectedUploads}
		{deleteConfirm}
		{deleting}
		{expanded}
		ontoggleexpand={toggleExpand}
		onconfirmchange={(value) => deleteConfirm = value}
		ondeletemanifest={deleteByReference}
		ondeletetag={deleteByReference}
		oncancelupload={cancelUpload}
		onuploadselectionchange={(selected) => selectedUploads = selected}
		oncancelselecteduploads={cancelSelectedUploads}
	/>
{/if}
