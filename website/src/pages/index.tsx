import React from 'react';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={styles.heroBanner}>
      <div className="container">
        <div className={styles.heroContent}>
          <h1 className={styles.heroTitle}>SIMPLE-REGISTRY</h1>
          <p className={styles.heroSubtitle}>{siteConfig.tagline}</p>
          <div className={styles.buttons}>
            <Link className={styles.button} to="/docs/tutorials/quickstart">
              [quickstart]
            </Link>
            <Link className={styles.buttonSecondary} to="/docs/reference/configuration">
              [configuration]
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}

const features = [
  {
    title: 'OCI-Compliant',
    description: 'Full OCI Distribution Specification v1.1 support. Works with Docker, Podman, containerd, and any OCI-compatible tooling.',
  },
  {
    title: 'Pull-Through Cache',
    description: 'Mirror Docker Hub, ghcr.io, or any registry. Intelligent caching with immutable tag optimization.',
  },
  {
    title: 'CEL Policies',
    description: 'Fine-grained access control using Common Expression Language. Define who can push, pull, or delete.',
  },
  {
    title: 'OIDC Authentication',
    description: 'Native support for GitHub Actions, Google, Okta, and any OIDC provider. Passwordless CI/CD.',
  },
  {
    title: 'Retention Policies',
    description: 'Automated cleanup with flexible rules. Keep latest, semver tags, or top-k most used images.',
  },
  {
    title: 'Web UI',
    description: 'Browse repositories with clear manifest hierarchy, ORAS artifact downloads, and automatic detection of signatures, SBOMs, and SLSA attestations.',
  },
];

function Feature({title, description}: {title: string; description: string}) {
  return (
    <div className={styles.feature}>
      <h3 className={styles.featureTitle}>{title}</h3>
      <p className={styles.featureDescription}>{description}</p>
    </div>
  );
}

function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <h2 className={styles.sectionTitle}>FEATURES</h2>
        <div className={styles.featureGrid}>
          {features.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

function HomepageQuickStart() {
  return (
    <section className={styles.quickstart}>
      <div className="container">
        <h2 className={styles.sectionTitle}>QUICK START</h2>
        <div className={styles.codeBlock}>
          <pre>
            <code>
{`# Download
curl -LO https://github.com/simple-registry/simple-registry/releases/latest/download/simple-registry-linux-amd64
chmod +x simple-registry-linux-amd64

# Configure
cat > config.toml << EOF
[server]
bind_address = "0.0.0.0"
port = 5000

[blob_store.fs]
root_dir = "./data"

[global.access_policy]
default_allow = true

[repository."myrepo"]
EOF

# Run
./simple-registry-linux-amd64 -c config.toml server`}
            </code>
          </pre>
        </div>
        <div className={styles.buttons} style={{marginTop: '2rem'}}>
          <Link className={styles.button} to="/docs/tutorials/quickstart">
            [full tutorial]
          </Link>
        </div>
      </div>
    </section>
  );
}

function HomepageLinks() {
  return (
    <section className={styles.links}>
      <div className="container">
        <div className={styles.linkGrid}>
          <Link to="/docs/tutorials/quickstart" className={styles.linkCard}>
            <h3>Learn</h3>
            <p>Step-by-step tutorials for getting started</p>
          </Link>
          <Link to="/docs/how-to/deploy-docker-compose" className={styles.linkCard}>
            <h3>Guides</h3>
            <p>Task-oriented how-to instructions</p>
          </Link>
          <Link to="/docs/reference/configuration" className={styles.linkCard}>
            <h3>Reference</h3>
            <p>Configuration and API documentation</p>
          </Link>
          <Link to="/docs/explanation/architecture" className={styles.linkCard}>
            <h3>Concepts</h3>
            <p>Architecture and design explanations</p>
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): React.JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title="Home"
      description={siteConfig.tagline}>
      <HomepageHeader />
      <main>
        <HomepageFeatures />
        <HomepageQuickStart />
        <HomepageLinks />
      </main>
    </Layout>
  );
}
