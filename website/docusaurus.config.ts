import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Angos',
  tagline: 'A lightweight, OCI-compliant container registry',
  favicon: 'img/logo.svg',

  url: 'https://angos.github.io',
  baseUrl: '/angos/',

  organizationName: 'angos',
  projectName: 'angos',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
  },

  themes: ['@docusaurus/theme-mermaid'],

  presets: [
    [
      'classic',
      {
        docs: {
          path: '../doc',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/project-angos/angos/tree/main/',
        },
        pages: {},
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    image: 'img/social-card.png',
    navbar: {
      title: 'ANGOS',
      logo: {
        alt: 'Angos Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'dropdown',
          label: 'Learn',
          position: 'left',
          items: [
            {to: '/docs/tutorials/quickstart', label: 'Quickstart'},
            {to: '/docs/tutorials/your-first-private-registry', label: 'Private Registry'},
            {to: '/docs/tutorials/mirror-docker-hub', label: 'Mirror Docker Hub'},
          ],
        },
        {
          type: 'dropdown',
          label: 'Guides',
          position: 'left',
          items: [
            {to: '/docs/how-to/deploy-docker-compose', label: 'Deploy with Docker Compose'},
            {to: '/docs/how-to/deploy-kubernetes', label: 'Deploy on Kubernetes'},
            {type: 'html', value: '<hr style="margin: 0.5rem 0; border-color: var(--ifm-toc-border-color);">'},
            {to: '/docs/how-to/configure-mtls', label: 'Configure mTLS'},
            {to: '/docs/how-to/configure-github-actions-oidc', label: 'GitHub Actions OIDC'},
            {to: '/docs/how-to/configure-generic-oidc', label: 'Generic OIDC'},
            {type: 'html', value: '<hr style="margin: 0.5rem 0; border-color: var(--ifm-toc-border-color);">'},
            {to: '/docs/how-to/set-up-access-control', label: 'Access Control'},
            {to: '/docs/how-to/configure-retention-policies', label: 'Retention Policies'},
            {to: '/docs/how-to/protect-tags-immutability', label: 'Immutable Tags'},
            {to: '/docs/how-to/configure-webhook-authorization', label: 'Webhook Authorization'},
            {type: 'html', value: '<hr style="margin: 0.5rem 0; border-color: var(--ifm-toc-border-color);">'},
            {to: '/docs/how-to/run-storage-maintenance', label: 'Storage Maintenance'},
            {to: '/docs/how-to/enable-web-ui', label: 'Enable Web UI'},
            {to: '/docs/how-to/troubleshoot-common-issues', label: 'Troubleshooting'},
          ],
        },
        {
          type: 'dropdown',
          label: 'Reference',
          position: 'left',
          items: [
            {to: '/docs/reference/configuration', label: 'Configuration'},
            {to: '/docs/reference/cli', label: 'CLI'},
            {to: '/docs/reference/cel-expressions', label: 'CEL Expressions'},
            {to: '/docs/reference/api-endpoints', label: 'API Endpoints'},
            {to: '/docs/reference/ui', label: 'Web UI'},
            {to: '/docs/reference/metrics', label: 'Metrics'},
          ],
        },
        {
          type: 'dropdown',
          label: 'Concepts',
          position: 'left',
          items: [
            {to: '/docs/explanation/architecture', label: 'Architecture'},
            {to: '/docs/explanation/storage-backends', label: 'Storage Backends'},
            {to: '/docs/explanation/authentication-authorization', label: 'Authentication'},
            {to: '/docs/explanation/pull-through-caching', label: 'Pull-Through Caching'},
            {to: '/docs/explanation/security-model', label: 'Security Model'},
          ],
        },
        {
          href: 'https://github.com/project-angos/angos',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Learn',
          items: [
            {label: 'Quickstart', to: '/docs/tutorials/quickstart'},
            {label: 'Private Registry', to: '/docs/tutorials/your-first-private-registry'},
            {label: 'Mirror Docker Hub', to: '/docs/tutorials/mirror-docker-hub'},
          ],
        },
        {
          title: 'Guides',
          items: [
            {label: 'Docker Compose', to: '/docs/how-to/deploy-docker-compose'},
            {label: 'Kubernetes', to: '/docs/how-to/deploy-kubernetes'},
            {label: 'Access Control', to: '/docs/how-to/set-up-access-control'},
            {label: 'Troubleshooting', to: '/docs/how-to/troubleshoot-common-issues'},
          ],
        },
        {
          title: 'Reference',
          items: [
            {label: 'Configuration', to: '/docs/reference/configuration'},
            {label: 'CLI', to: '/docs/reference/cli'},
            {label: 'API Endpoints', to: '/docs/reference/api-endpoints'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'GitHub', href: 'https://github.com/project-angos/angos'},
            {label: 'Issues', href: 'https://github.com/project-angos/angos/issues'},
            {label: 'Releases', href: 'https://github.com/project-angos/angos/releases'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Angos.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'toml', 'yaml', 'rust', 'json'],
    },
    mermaid: {
      theme: {light: 'neutral', dark: 'dark'},
    },
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
