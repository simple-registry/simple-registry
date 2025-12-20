<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchManifest, fetchRevisions, deleteManifest, downloadBlob as apiDownloadBlob, type ParentRef, type Manifest, type ReferrerInfo } from '$lib/api';
	import { formatSize, displayNamespace as displayNs, isOrasArtifact, getFileName, getTagConfirm, repoUrl, namespaceUrl, manifestUrl, tagConfirmKey, getAttestationType } from '$lib/utils';
	import LoadingState from '$lib/components/LoadingState.svelte';
	import ErrorState from '$lib/components/ErrorState.svelte';
	import Breadcrumb from '$lib/components/Breadcrumb.svelte';
	import Card from '$lib/components/Card.svelte';
	import DeleteButton from '$lib/components/DeleteButton.svelte';
	import TagList from '$lib/components/TagList.svelte';
	import PlatformBadge from '$lib/components/PlatformBadge.svelte';
	import AttestationBadge from '$lib/components/AttestationBadge.svelte';
	import AnnotationToggle from '$lib/components/AnnotationToggle.svelte';
	import AnnotationList from '$lib/components/AnnotationList.svelte';
	import DigestLink from '$lib/components/DigestLink.svelte';
	import type { PageData } from './$types';

	let { data }: { data: PageData } = $props();

	async function downloadBlob(blobDigest: string, filename: string | null) {
		const err = await apiDownloadBlob(data.namespace, blobDigest, filename);
		if (err) {
			error = err;
		}
	}

	type LayersViewMode = 'auto' | 'files' | 'layers';

	let manifest: Manifest | null = $state(null);
	let digest: string | null = $state(null);
	let tags: string[] = $state([]);
	let referencedBy: ParentRef[] = $state([]);
	let childReferrers: Map<string, ReferrerInfo[]> = $state(new Map());
	let loading = $state(true);
	let error: string | null = $state(null);
	let deleteConfirm: string | null = $state(null);
	let deleting = $state(false);
	let expandedAnnotations: Set<string> = $state(new Set());
	let layersViewMode: LayersViewMode = $state('auto');

	const showFilesView = $derived(
		layersViewMode === 'auto'
			? (manifest ? isOrasArtifact(manifest) : false)
			: layersViewMode === 'files'
	);

	function toggleAnnotations(key: string) {
		if (expandedAnnotations.has(key)) {
			expandedAnnotations.delete(key);
		} else {
			expandedAnnotations.add(key);
		}
		expandedAnnotations = new Set(expandedAnnotations);
	}

	$effect(() => {
		loadManifest(data.namespace, data.reference);
	});

	async function loadManifest(namespace: string, reference: string) {
		loading = true;
		error = null;
		tags = [];
		referencedBy = [];
		childReferrers = new Map();

		const result = await fetchManifest(namespace, reference);
		if (result.error) {
			error = result.error;
			loading = false;
			return;
		}

		manifest = result.manifest;
		digest = result.digest;

		if (digest) {
			const revisionsResult = await fetchRevisions(namespace);
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

	async function deleteTag(tag: string) {
		deleting = true;
		error = null;
		const err = await deleteManifest(data.namespace, tag);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			await loadManifest(data.namespace, data.reference);
		}
		deleting = false;
	}

	async function deleteByHash() {
		if (!digest) return;
		deleting = true;
		error = null;
		const err = await deleteManifest(data.namespace, digest);
		if (err) {
			error = err;
			deleting = false;
		} else {
			window.location.href = namespaceUrl(data.repository, data.namespace);
		}
	}

	function handleRowClick(event: MouseEvent, targetDigest: string) {
		const target = event.target as HTMLElement;
		if (target.tagName === 'BUTTON' || target.closest('button') ||
			target.tagName === 'A' || target.closest('a')) {
			return;
		}
		goto(manifestUrl(data.repository, data.namespace, targetDigest));
	}

</script>

<svelte:head>
	<title>{data.reference} // {displayNs(data.namespace, data.repository)} // {data.repository} // {getRegistryName()}</title>
</svelte:head>

<Breadcrumb items={[
	{ label: 'repositories', href: `${base}/` },
	{ label: data.repository, href: repoUrl(data.repository) },
	{ label: displayNs(data.namespace, data.repository), href: namespaceUrl(data.repository, data.namespace) },
	{ label: data.reference }
]} />

{#if loading}
	<LoadingState message="loading manifest" />
{:else if error}
	<ErrorState message={error} />
{:else if manifest}
	<Card title="manifest">
		<table>
			<tbody>
				<tr>
					<td class="label">digest</td>
					<td><code>{digest}</code></td>
				</tr>
				<tr>
					<td class="label">tags</td>
					<td>
						<TagList
							{tags}
							deleteConfirm={getTagConfirm(deleteConfirm)}
							disabled={deleting}
							ondelete={deleteTag}
							onconfirmchange={(tag) => deleteConfirm = tag ? tagConfirmKey(tag) : null}
						/>
					</td>
				</tr>
				<tr>
					<td class="label">media_type</td>
					<td>
						{manifest.mediaType ?? 'unknown'}
						{#if manifest.annotations}
							<AnnotationToggle expanded={expandedAnnotations.has('root')} ontoggle={() => toggleAnnotations('root')} />
						{/if}
					</td>
				</tr>
				{#if manifest.annotations && expandedAnnotations.has('root')}
					<AnnotationList annotations={manifest.annotations} />
				{/if}
				{#if manifest.artifactType}
					<tr>
						<td class="label">artifact_type</td>
						<td>{manifest.artifactType}</td>
					</tr>
				{/if}
				{#if manifest.subject}
					<tr>
						<td class="label">subject</td>
						<td>
							<DigestLink
								digest={manifest.subject.digest}
								href={manifestUrl(data.repository, data.namespace, manifest.subject.digest)}
							/>
							<span class="subject-meta">({manifest.subject.mediaType}, {formatSize(manifest.subject.size)})</span>
						</td>
					</tr>
				{/if}
				<tr>
					<td class="label">actions</td>
					<td>
						<DeleteButton
							isConfirming={deleteConfirm === 'digest'}
							disabled={deleting}
							onconfirm={deleteByHash}
							oncancel={() => deleteConfirm = null}
							onrequestconfirm={() => deleteConfirm = 'digest'}
						/>
					</td>
				</tr>
			</tbody>
		</table>
	</Card>

	{#if manifest.config}
		<Card title="config">
			<table>
				<tbody>
					<tr>
						<td class="label">digest</td>
						<td>
							<DigestLink
								digest={manifest.config.digest}
								annotations={manifest.config.annotations}
								expanded={expandedAnnotations.has('config')}
								ontoggle={() => toggleAnnotations('config')}
							/>
						</td>
					</tr>
					<tr>
						<td class="label">media_type</td>
						<td>{manifest.config.mediaType}</td>
					</tr>
					<tr>
						<td class="label">size</td>
						<td>{formatSize(manifest.config.size)}</td>
					</tr>
					{#if manifest.config.annotations && expandedAnnotations.has('config')}
						<AnnotationList annotations={manifest.config.annotations} />
					{/if}
				</tbody>
			</table>
		</Card>
	{/if}

	{#if manifest.layers && manifest.layers.length > 0}
		{#snippet viewToggle()}
			<div class="view-toggle">
				<button class:active={layersViewMode === 'auto'} onclick={() => layersViewMode = 'auto'}>auto</button>
				<button class:active={layersViewMode === 'files'} onclick={() => layersViewMode = 'files'}>files</button>
				<button class:active={layersViewMode === 'layers'} onclick={() => layersViewMode = 'layers'}>layers</button>
			</div>
		{/snippet}
		{#if showFilesView}
			<Card title="files" count={manifest.layers.length} headerActions={viewToggle}>
				<table>
					<thead>
						<tr>
							<th>name</th>
							<th>type</th>
							<th class="col-narrow">size</th>
							<th class="col-narrow"></th>
						</tr>
					</thead>
					<tbody>
						{#each manifest.layers as layer}
							<tr>
								<td class="filename">{getFileName(layer) ?? layer.digest}</td>
								<td>{layer.mediaType}</td>
								<td>{formatSize(layer.size)}</td>
								<td>
									<button class="download-link" onclick={() => downloadBlob(layer.digest, getFileName(layer))}>download</button>
								</td>
							</tr>
						{/each}
					</tbody>
					<tfoot>
						<tr>
							<td colspan="2" class="total-label">total</td>
							<td>{formatSize(manifest.layers.reduce((sum, l) => sum + l.size, 0))}</td>
							<td></td>
						</tr>
					</tfoot>
				</table>
			</Card>
		{:else}
			<Card title="layers" count={manifest.layers.length} headerActions={viewToggle}>
				<table>
					<thead>
						<tr>
							<th>digest</th>
							<th>media_type</th>
							<th class="col-narrow">size</th>
						</tr>
					</thead>
					<tbody>
						{#each manifest.layers as layer}
							<tr>
								<td>
									<DigestLink
										digest={layer.digest}
										annotations={layer.annotations}
										expanded={expandedAnnotations.has(`layer:${layer.digest}`)}
										ontoggle={() => toggleAnnotations(`layer:${layer.digest}`)}
									/>
								</td>
								<td>{layer.mediaType}</td>
								<td>{formatSize(layer.size)}</td>
							</tr>
							{#if layer.annotations && expandedAnnotations.has(`layer:${layer.digest}`)}
								<tr class="annotations-row">
									<td colspan="3">
										<AnnotationList annotations={layer.annotations} format="inline" />
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
					<tfoot>
						<tr>
							<td colspan="2" class="total-label">total</td>
							<td>{formatSize(manifest.layers.reduce((sum, l) => sum + l.size, 0))}</td>
						</tr>
					</tfoot>
				</table>
			</Card>
		{/if}
	{/if}

	{#if manifest.manifests && manifest.manifests.length > 0}
		{@const platformManifests = manifest.manifests.filter(m => !m.annotations?.['vnd.docker.reference.digest'])}
		{#if platformManifests.length > 0}
		<Card title="manifests" count={platformManifests.length}>
			<table>
				<thead>
					<tr>
						<th>digest</th>
						<th>platform</th>
						<th>media_type</th>
						<th class="col-narrow">size</th>
					</tr>
				</thead>
				<tbody>
					{#each platformManifests as m}
						{@const refs = childReferrers.get(m.digest) ?? []}
						{@const hasRefs = refs.length > 0}
						<tr class="child-row clickable" onclick={(e) => handleRowClick(e, m.digest)}>
							<td class="has-children" class:expanded={hasRefs}>
								<span class="tree-toggle leaf"></span>
								<DigestLink
									digest={m.digest}
									href={manifestUrl(data.repository, data.namespace, m.digest)}
									annotations={m.annotations}
									expanded={expandedAnnotations.has(`manifest:${m.digest}`)}
									ontoggle={() => toggleAnnotations(`manifest:${m.digest}`)}
								/>
							</td>
							<td>
								<PlatformBadge platform={m.platform} />
							</td>
							<td>{m.mediaType}</td>
							<td>{formatSize(m.size)}</td>
						</tr>
						{#if m.annotations && expandedAnnotations.has(`manifest:${m.digest}`)}
							<tr class="annotations-row">
								<td colspan="4">
									<AnnotationList annotations={m.annotations} format="inline" />
								</td>
							</tr>
						{/if}
						{#each refs as ref, ridx}
							{@const isLastRef = ridx === refs.length - 1}
							<tr class="child-row clickable" onclick={(e) => handleRowClick(e, ref.digest)}>
								<td class="tree-branch" class:has-next={!isLastRef}>
									<span class="tree-toggle leaf"></span>
									<DigestLink
										digest={ref.digest}
										href={manifestUrl(data.repository, data.namespace, ref.digest)}
									/>
								</td>
								<td><AttestationBadge type={getAttestationType(ref)} /></td>
								<td></td>
								<td></td>
							</tr>
						{/each}
					{/each}
				</tbody>
			</table>
		</Card>
		{/if}
	{/if}

	{#if referencedBy.length > 0}
		<Card title="referenced by" count={referencedBy.length}>
			<table>
				<thead>
					<tr>
						<th>digest</th>
						<th>tags</th>
						<th>platform</th>
					</tr>
				</thead>
				<tbody>
					{#each referencedBy as parent}
						<tr class="clickable" onclick={(e) => handleRowClick(e, parent.digest)}>
							<td>
								<DigestLink
									digest={parent.digest}
									href={manifestUrl(data.repository, data.namespace, parent.digest)}
								/>
							</td>
							<td>
								<TagList tags={parent.tags} />
							</td>
							<td>
								<PlatformBadge platform={parent.platform} />
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</Card>
	{/if}
{/if}
