import { base } from '$app/paths';
import type { ManifestEntry, Platform, Manifest, Descriptor } from './api';

export interface TreeNode {
	manifest: ManifestEntry;
	children: { manifest: ManifestEntry; platform?: Platform }[];
}

export function repoUrl(name: string): string {
	return `${base}/${encodeURIComponent(name)}`;
}

export function namespaceUrl(repo: string, namespace: string): string {
	return `${base}/${encodeURIComponent(repo)}/${encodeURIComponent(namespace)}`;
}

export function manifestUrl(repo: string, namespace: string, reference: string): string {
	return `${base}/${encodeURIComponent(repo)}/${encodeURIComponent(namespace)}/${encodeURIComponent(reference)}`;
}

export function digestConfirmKey(digest: string): string {
	return `digest:${digest}`;
}

export function tagConfirmKey(tag: string): string {
	return `tag:${tag}`;
}

export function uploadConfirmKey(uuid: string): string {
	return `upload:${uuid}`;
}

const WELL_KNOWN_ANNOTATIONS: Record<string, string> = {
	'org.opencontainers.image.created': 'created',
	'org.opencontainers.image.authors': 'authors',
	'org.opencontainers.image.url': 'url',
	'org.opencontainers.image.documentation': 'documentation',
	'org.opencontainers.image.source': 'source',
	'org.opencontainers.image.version': 'version',
	'org.opencontainers.image.revision': 'revision',
	'org.opencontainers.image.vendor': 'vendor',
	'org.opencontainers.image.licenses': 'licenses',
	'org.opencontainers.image.title': 'title',
	'org.opencontainers.image.description': 'description',
	'org.opencontainers.image.base.digest': 'base_digest',
	'org.opencontainers.image.base.name': 'base_name',
};

export function formatSize(bytes: number): string {
	const units = ['B', 'KB', 'MB', 'GB'];
	let i = 0;
	let size = bytes;
	while (size >= 1024 && i < units.length - 1) {
		size /= 1024;
		i++;
	}
	return `${size.toFixed(1)} ${units[i]}`;
}

export function formatPlatform(platform?: Platform): string {
	if (!platform) return '';
	let result = `${platform.os}/${platform.architecture}`;
	if (platform.variant) {
		result += `/${platform.variant}`;
	}
	return result;
}

export function formatTimeAgo(dateString: string): string {
	const date = new Date(dateString);
	const now = new Date();
	const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);

	if (seconds < 60) return `${seconds}s ago`;
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${minutes}m ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 24) return `${hours}h ago`;
	const days = Math.floor(hours / 24);
	return `${days}d ago`;
}

export function displayNamespace(namespace: string, repository: string): string {
	const prefix = repository + '/';
	if (namespace.startsWith(prefix)) {
		return namespace.slice(prefix.length);
	}
	return namespace;
}

export function buildTree(manifests: ManifestEntry[]): TreeNode[] {
	const childDigests = new Set<string>();
	const parentToChildren = new Map<string, { manifest: ManifestEntry; platform?: Platform }[]>();

	for (const m of manifests) {
		if (m.parents && m.parents.length > 0) {
			childDigests.add(m.digest);
			for (const parent of m.parents) {
				const children = parentToChildren.get(parent.digest) ?? [];
				children.push({ manifest: m, platform: parent.platform });
				parentToChildren.set(parent.digest, children);
			}
		}
	}

	const roots: TreeNode[] = [];
	for (const m of manifests) {
		if (!childDigests.has(m.digest)) {
			const children = parentToChildren.get(m.digest) ?? [];
			children.sort((a, b) => {
				const pa = formatPlatform(a.platform);
				const pb = formatPlatform(b.platform);
				return pa.localeCompare(pb);
			});
			roots.push({ manifest: m, children });
		}
	}

	roots.sort((a, b) => {
		if (a.manifest.tags.length > 0 && b.manifest.tags.length === 0) return -1;
		if (a.manifest.tags.length === 0 && b.manifest.tags.length > 0) return 1;
		return 0;
	});

	return roots;
}

export function getTagConfirm(deleteConfirm: string | null): string | null {
	if (deleteConfirm?.startsWith('tag:')) {
		return deleteConfirm.slice(4);
	}
	return null;
}

export function getAnnotationLabel(key: string): string {
	return WELL_KNOWN_ANNOTATIONS[key] ?? key;
}

export function isUrl(value: string): boolean {
	return value.startsWith('http://') || value.startsWith('https://');
}

export function isOrasArtifact(m: Manifest): boolean {
	if (m.artifactType) return true;
	if (m.config?.mediaType === 'application/vnd.oci.empty.v1+json') return true;
	return m.layers?.some(l => l.annotations?.['org.opencontainers.image.title']) ?? false;
}

export function getFileName(layer: Descriptor): string | null {
	return layer.annotations?.['org.opencontainers.image.title'] ?? null;
}
