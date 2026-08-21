<script lang="ts">
	import { goto } from '$app/navigation';
	import type { ParentRef, Manifest, ReferrerInfo } from '$lib/api';
	import {
		formatSize,
		getTagConfirm,
		isInteractiveTarget,
		manifestUrl,
		tagConfirmKey,
		getAttestationType,
		isOrasArtifact,
		getFileName
	} from '$lib/utils';
	import Card from './Card.svelte';
	import DeleteButton from './DeleteButton.svelte';
	import TagList from './TagList.svelte';
	import PlatformBadge from './PlatformBadge.svelte';
	import AttestationBadge from './AttestationBadge.svelte';
	import AnnotationToggle from './AnnotationToggle.svelte';
	import AnnotationList from './AnnotationList.svelte';
	import DigestLink from './DigestLink.svelte';
	import PullHistory from './PullHistory.svelte';

	interface Props {
		path: string;
		/** The tag or digest this view was addressed by; pulls are keyed by it. */
		reference: string;
		manifest: Manifest;
		digest: string | null;
		tags: string[];
		referencedBy: ParentRef[];
		childReferrers: Map<string, ReferrerInfo[]>;
		childReferrersNext: Map<string, string>;
		loadingReferrers: string | null;
		onloadmorereferrers: (childDigest: string) => void;
		deleteConfirm: string | null;
		deleting: boolean;
		ondeletetag: (tag: string) => void;
		ondeletebyhash: () => void;
		onconfirmchange: (value: string | null) => void;
		getbloburl: (blobDigest: string) => string;
	}

	let {
		path,
		reference,
		manifest,
		digest,
		tags,
		referencedBy,
		childReferrers,
		childReferrersNext,
		loadingReferrers,
		onloadmorereferrers,
		deleteConfirm,
		deleting,
		ondeletetag,
		ondeletebyhash,
		onconfirmchange,
		getbloburl
	}: Props = $props();

	let expandedAnnotations: Set<string> = $state(new Set());

	type LayersViewMode = 'auto' | 'files' | 'layers';
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

	function handleRowClick(event: MouseEvent, targetDigest: string) {
		if (isInteractiveTarget(event)) return;
		goto(manifestUrl(path, targetDigest));
	}
</script>

<Card title="Manifest">
	<table>
		<tbody>
			<tr>
				<td class="label">Digest</td>
				<td>
					<DigestLink
						digest={digest ?? ''}
						href={digest ? manifestUrl(path, digest) : undefined}
					/>
				</td>
			</tr>
			<tr>
				<td class="label">Tags</td>
				<td>
					<TagList
						{tags}
						deleteConfirm={getTagConfirm(deleteConfirm)}
						disabled={deleting}
						ondelete={ondeletetag}
						onconfirmchange={(tag) => onconfirmchange(tag ? tagConfirmKey(tag) : null)}
						getHref={(tag) => manifestUrl(path, tag)}
					/>
				</td>
			</tr>
			<tr>
				<td class="label">Media type</td>
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
					<td class="label">Artifact type</td>
					<td>{manifest.artifactType}</td>
				</tr>
			{/if}
			{#if manifest.subject}
				<tr>
					<td class="label">Subject</td>
					<td>
						<DigestLink
							digest={manifest.subject.digest}
							href={manifestUrl(path, manifest.subject.digest)}
						/>
						<span class="subject-meta">({manifest.subject.mediaType}, {formatSize(manifest.subject.size)})</span>
					</td>
				</tr>
			{/if}
			<tr>
				<td class="label">Actions</td>
				<td>
					<DeleteButton
						isConfirming={deleteConfirm === 'digest'}
						disabled={deleting}
						onconfirm={ondeletebyhash}
						oncancel={() => onconfirmchange(null)}
						onrequestconfirm={() => onconfirmchange('digest')}
					/>
				</td>
			</tr>
		</tbody>
	</table>
</Card>

<!-- Keyed on the reference so navigating to another manifest drops the
     collapsed state and the history fetched for the previous one. -->
{#key reference}
	<PullHistory namespace={path} target={reference} />
{/key}

{#if manifest.config}
	<Card title="Config">
		<table>
			<tbody>
				<tr>
					<td class="label">Digest</td>
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
					<td class="label">Media type</td>
					<td>{manifest.config.mediaType}</td>
				</tr>
				<tr>
					<td class="label">Size</td>
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
		<Card title="Files" count={manifest.layers.length} headerActions={viewToggle}>
			<table>
				<thead>
					<tr>
						<th>Name</th>
						<th>Type</th>
						<th class="col-narrow">Size</th>
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
								<a class="download-link" href={getbloburl(layer.digest)} download={getFileName(layer) ?? layer.digest}>Download</a>
							</td>
						</tr>
					{/each}
				</tbody>
				<tfoot>
					<tr>
						<td colspan="2" class="total-label">Total</td>
						<td>{formatSize(manifest.layers.reduce((sum, l) => sum + l.size, 0))}</td>
						<td></td>
					</tr>
				</tfoot>
			</table>
		</Card>
	{:else}
		<Card title="Layers" count={manifest.layers.length} headerActions={viewToggle}>
			<table>
				<thead>
					<tr>
						<th>Digest</th>
						<th>Media type</th>
						<th class="col-narrow">Size</th>
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
						<td colspan="2" class="total-label">Total</td>
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
	<Card title="Manifests" count={platformManifests.length}>
		<table>
			<thead>
				<tr>
					<th>Digest</th>
					<th>Platform</th>
					<th>Media type</th>
					<th class="col-narrow">Size</th>
				</tr>
			</thead>
			<tbody>
				{#each platformManifests as m}
					{@const refs = childReferrers.get(m.digest) ?? []}
					<tr class="child-row clickable" onclick={(e) => handleRowClick(e, m.digest)}>
						<td class="has-children" class:expanded={refs.length > 0}>
							<span class="tree-toggle leaf"></span>
							<DigestLink
								digest={m.digest}
								href={manifestUrl(path, m.digest)}
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
					{@const moreRefs = childReferrersNext.has(m.digest)}
					{#each refs as ref, ridx}
						{@const isLastRef = ridx === refs.length - 1 && !moreRefs}
						<tr class="child-row clickable" onclick={(e) => handleRowClick(e, ref.digest)}>
							<td class="tree-branch" class:has-next={!isLastRef}>
								<span class="tree-toggle leaf"></span>
								<DigestLink
									digest={ref.digest}
									href={manifestUrl(path, ref.digest)}
								/>
							</td>
							<td><AttestationBadge type={getAttestationType(ref)} /></td>
							<td></td>
							<td></td>
						</tr>
					{/each}
					{#if moreRefs}
						<tr class="child-row">
							<td class="tree-branch">
								<span class="tree-toggle leaf"></span>
								<button
									class="secondary"
									onclick={() => onloadmorereferrers(m.digest)}
									disabled={loadingReferrers === m.digest}
								>
									Load more referrers
								</button>
							</td>
							<td></td>
							<td></td>
							<td></td>
						</tr>
					{/if}
				{/each}
			</tbody>
		</table>
	</Card>
	{/if}
{/if}

{#if referencedBy.length > 0}
	<Card title="Referenced by" count={referencedBy.length}>
		<table>
			<thead>
				<tr>
					<th>Digest</th>
					<th>Tags</th>
					<th>Platform</th>
				</tr>
			</thead>
			<tbody>
				{#each referencedBy as parent}
					<tr class="clickable" onclick={(e) => handleRowClick(e, parent.digest)}>
						<td>
							<DigestLink
								digest={parent.digest}
								href={manifestUrl(path, parent.digest)}
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
