import type { PageLoad } from './$types';

export interface PathParams {
	repository: string;
	namespace: string;
	reference: string | null;
}

export const load: PageLoad = ({ params }): PathParams => {
	const pathSegments = params.path.split('/');
	const lastSegment = pathSegments[pathSegments.length - 1];

	const tagIndex = lastSegment.lastIndexOf(':');
	const digestIndex = lastSegment.indexOf('@');

	if (digestIndex !== -1) {
		const namespacePart = lastSegment.slice(0, digestIndex);
		const reference = lastSegment.slice(digestIndex + 1);
		const namespace = [...pathSegments.slice(0, -1), namespacePart].filter(Boolean).join('/');
		return { repository: params.repository, namespace, reference };
	}

	if (tagIndex !== -1) {
		const namespacePart = lastSegment.slice(0, tagIndex);
		const reference = lastSegment.slice(tagIndex + 1);
		const namespace = [...pathSegments.slice(0, -1), namespacePart].filter(Boolean).join('/');
		return { repository: params.repository, namespace, reference };
	}

	return {
		repository: params.repository,
		namespace: pathSegments.join('/'),
		reference: null
	};
};
