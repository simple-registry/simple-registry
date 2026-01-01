import {visit} from 'unist-util-visit';

export default function remarkThemedImages() {
  return (tree) => {
    visit(tree, (node) => {
      if (node.type === 'mdxJsxFlowElement' && node.name === 'picture') {
        transformPicture(node);
      }
    });
  };
}

function transformPicture(node) {
  let darkSrc = '';
  let lightSrc = '';
  let alt = '';

  for (const child of node.children || []) {
    if (child.name === 'source') {
      const media = child.attributes?.find(a => a.name === 'media')?.value || '';
      const srcset = child.attributes?.find(a => a.name === 'srcset' || a.name === 'srcSet')?.value || '';
      if (media.includes('dark')) {
        darkSrc = srcset;
      } else if (media.includes('light')) {
        lightSrc = srcset;
      }
    } else if (child.name === 'img') {
      alt = child.attributes?.find(a => a.name === 'alt')?.value || '';
      if (!lightSrc) {
        lightSrc = child.attributes?.find(a => a.name === 'src')?.value || '';
      }
    }
  }

  if (!darkSrc) darkSrc = lightSrc;

  node.name = 'span';
  node.attributes = [
    {type: 'mdxJsxAttribute', name: 'className', value: 'themed-image'}
  ];
  node.children = [
    {
      type: 'mdxJsxFlowElement',
      name: 'img',
      attributes: [
        {type: 'mdxJsxAttribute', name: 'src', value: lightSrc},
        {type: 'mdxJsxAttribute', name: 'alt', value: alt},
        {type: 'mdxJsxAttribute', name: 'className', value: 'light-only'},
      ],
      children: [],
    },
    {
      type: 'mdxJsxFlowElement',
      name: 'img',
      attributes: [
        {type: 'mdxJsxAttribute', name: 'src', value: darkSrc},
        {type: 'mdxJsxAttribute', name: 'alt', value: alt},
        {type: 'mdxJsxAttribute', name: 'className', value: 'dark-only'},
      ],
      children: [],
    },
  ];
}
