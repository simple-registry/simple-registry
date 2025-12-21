<script lang="ts">
	import { goto } from '$app/navigation';
	import { base } from '$app/paths';
	import { getRegistryName } from '$lib/config.svelte';
	import { fetchRevisions, fetchUploads, fetchManifest, deleteManifest as apiDeleteManifest, cancelUpload as apiCancelUpload, downloadBlob as apiDownloadBlob, type UploadEntry, type ParentRef, type Manifest, type ReferrerInfo } from '$lib/api';
	import { formatSize, formatTimeAgo, displayNamespace as displayNs, buildTree, getTagConfirm, repoUrl, namespaceUrl, manifestUrl, digestConfirmKey, tagConfirmKey, uploadConfirmKey, getAttestationType, isOrasArtifact, getFileName, type TreeNode } from '$lib/utils';
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
	import type { PathParams } from './+page';

	let { data }: { data: PathParams } = $props();

	const isManifestView = $derived(data.reference !== null);
	const fullNamespace = $derived(`${data.repository}/${data.namespace}`);

	let tree: TreeNode[] = $state([]);
	let uploads: UploadEntry[] = $state([]);

	let manifest: Manifest | null = $state(null);
	let digest: string | null = $state(null);
	let tags: string[] = $state([]);
	let referencedBy: ParentRef[] = $state([]);
	let childReferrers: Map<string, ReferrerInfo[]> = $state(new Map());

	let loading = $state(true);
	let error: string | null = $state(null);
	let deleteConfirm: string | null = $state(null);
	let deleting = $state(false);
	let expanded: Set<string> = $state(new Set());
	let expandedAnnotations: Set<string> = $state(new Set());

	type LayersViewMode = 'auto' | 'files' | 'layers';
	let layersViewMode: LayersViewMode = $state('auto');

	const showFilesView = $derived(
		layersViewMode === 'auto'
			? (manifest ? isOrasArtifact(manifest) : false)
			: layersViewMode === 'files'
	);

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

	function toggleAnnotations(key: string) {
		if (expandedAnnotations.has(key)) {
			expandedAnnotations.delete(key);
		} else {
			expandedAnnotations.add(key);
		}
		expandedAnnotations = new Set(expandedAnnotations);
	}

	function hasChildren(node: TreeNode): boolean {
		return node.children.length > 0 || node.attestations.length > 0;
	}

	function hasReferrers(referrers: { digest: string }[] | undefined): boolean {
		return (referrers?.length ?? 0) > 0;
	}

	$effect(() => {
		if (data.reference !== null) {
			loadManifest(fullNamespace, data.reference);
		} else {
			loadNamespace(fullNamespace);
		}
	});

	async function loadNamespace(namespace: string) {
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

	async function deleteManifestByRef(reference: string) {
		deleting = true;
		error = null;
		const err = await apiDeleteManifest(fullNamespace, reference);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			if (data.reference !== null) {
				await loadManifest(fullNamespace, data.reference);
			} else {
				await loadNamespace(fullNamespace);
			}
		}
		deleting = false;
	}

	async function deleteTag(tag: string) {
		deleting = true;
		error = null;
		const err = await apiDeleteManifest(fullNamespace, tag);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			if (data.reference !== null) {
				await loadManifest(fullNamespace, data.reference);
			} else {
				await loadNamespace(fullNamespace);
			}
		}
		deleting = false;
	}

	async function deleteByHash() {
		if (!digest) return;
		deleting = true;
		error = null;
		const err = await apiDeleteManifest(fullNamespace, digest);
		if (err) {
			error = err;
			deleting = false;
		} else {
			window.location.href = namespaceUrl(data.repository, data.namespace);
		}
	}

	async function cancelUpload(uuid: string) {
		deleting = true;
		error = null;
		const err = await apiCancelUpload(fullNamespace, uuid);
		if (err) {
			error = err;
		} else {
			deleteConfirm = null;
			await loadNamespace(fullNamespace);
		}
		deleting = false;
	}

	async function downloadBlob(blobDigest: string, filename: string | null) {
		const err = await apiDownloadBlob(fullNamespace, blobDigest, filename);
		if (err) {
			error = err;
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
	{#if isManifestView}
		<title>{data.reference} // {displayNs(data.namespace, data.repository)} // {data.repository} // {getRegistryName()}</title>
	{:else}
		<title>{displayNs(data.namespace, data.repository)} // {data.repository} // {getRegistryName()}</title>
	{/if}
</svelte:head>

{#if isManifestView}
	<Breadcrumb items={[
		{ label: 'repositories', href: `${base}/` },
		{ label: data.repository, href: repoUrl(data.repository) },
		{ label: displayNs(data.namespace, data.repository), href: namespaceUrl(data.repository, data.namespace) },
		{ label: data.reference ?? '' }
	]} />
{:else}
	<Breadcrumb items={[
		{ label: 'repositories', href: `${base}/` },
		{ label: data.repository, href: repoUrl(data.repository) },
		{ label: displayNs(data.namespace, data.repository) }
	]} />
{/if}

{#if loading}
	<LoadingState message={isManifestView ? 'loading manifest' : 'loading'} />
{:else if error}
	<ErrorState message={error} />
{:else if isManifestView && manifest}
	<Card title="manifest">
		<table>
			<tbody>
				<tr>
					<td class="label">digest</td>
					<td>
						<DigestLink
							digest={digest ?? ''}
							href={digest ? manifestUrl(data.repository, data.namespace, digest) : undefined}
						/>
					</td>
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
							getHref={(tag) => manifestUrl(data.repository, data.namespace, tag)}
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
				<th>pushed</th>
				<th>pulled</th>
				<th class="col-narrow">actions</th>
			</tr>
		</thead>
		<tbody>
			{#if tree.length === 0}
				<tr>
					<td colspan="5" class="empty">no manifests found</td>
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
							getHref={(tag) => manifestUrl(data.repository, data.namespace, tag)}
						/>
					</td>
					<td>{node.manifest.pushed_at ? formatTimeAgo(node.manifest.pushed_at) : '-'}</td>
					<td>{node.manifest.last_pulled_at ? formatTimeAgo(node.manifest.last_pulled_at) : '-'}</td>
					<td>
						<DeleteButton
							isConfirming={deleteConfirm === digestConfirmKey(node.manifest.digest)}
							disabled={deleting}
							onconfirm={() => deleteManifestByRef(node.manifest.digest)}
							oncancel={() => deleteConfirm = null}
							onrequestconfirm={() => deleteConfirm = digestConfirmKey(node.manifest.digest)}
						/>
					</td>
				</tr>
				{#if nodeExpanded}
				{#each node.children as child, idx}
					{@const childManifestReferrers = child.manifest.referrers ?? []}
					{@const hasChildReferrers = hasReferrers(childManifestReferrers)}
					{@const childExpanded = expanded.has(child.manifest.digest)}
					{@const isLast = idx === node.children.length - 1 && node.attestations.length === 0}
					<tr class="child-row clickable" onclick={(e) => handleRowClick(e, child.manifest.digest)}>
						<td class="tree-branch" class:has-next={!isLast} class:has-attestations={hasChildReferrers && childExpanded}>
							{#if hasChildReferrers}<button class="tree-toggle" onclick={(e) => toggleExpand(child.manifest.digest, e)}><span class="toggle-icon">{childExpanded ? '−' : '+'}</span></button>{#if childExpanded}<span class="branch-line"></span>{/if}{:else}<span class="tree-toggle leaf"></span>{/if}<code>{child.manifest.digest}</code>
						</td>
						<td>
							<PlatformBadge platform={child.platform} />
						</td>
						<td>{child.manifest.pushed_at ? formatTimeAgo(child.manifest.pushed_at) : '-'}</td>
						<td>{child.manifest.last_pulled_at ? formatTimeAgo(child.manifest.last_pulled_at) : '-'}</td>
						<td>
							<DeleteButton
								isConfirming={deleteConfirm === digestConfirmKey(child.manifest.digest)}
								disabled={deleting}
								onconfirm={() => deleteManifestByRef(child.manifest.digest)}
								oncancel={() => deleteConfirm = null}
								onrequestconfirm={() => deleteConfirm = digestConfirmKey(child.manifest.digest)}
							/>
						</td>
					</tr>
					{#if childExpanded}
					{#each childManifestReferrers as referrer, ridx}
						{@const isLastRef = ridx === childManifestReferrers.length - 1}
						<tr class="child-row clickable" onclick={(e) => handleRowClick(e, referrer.digest)}>
							<td class="nested-tree-branch" class:has-next={!isLastRef}>
								{#if !isLast}<span class="parent-line"></span>{/if}<span class="tree-toggle leaf"></span><code>{referrer.digest}</code>
							</td>
							<td>
								<AttestationBadge type={getAttestationType(referrer)} />
							</td>
							<td></td>
							<td></td>
							<td>
								<DeleteButton
									isConfirming={deleteConfirm === digestConfirmKey(referrer.digest)}
									disabled={deleting}
									onconfirm={() => deleteManifestByRef(referrer.digest)}
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
						<td></td>
						<td></td>
						<td>
							<DeleteButton
								isConfirming={deleteConfirm === digestConfirmKey(att.digest)}
								disabled={deleting}
								onconfirm={() => deleteManifestByRef(att.digest)}
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
