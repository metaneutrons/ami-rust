// Documentation version switcher and banner.
//
// Published once at the site root as /version-switcher.js and added to every
// page of every version by rebase-site.mjs. It reads /versions.json at run
// time, so older versions learn about newer releases without being rebuilt.
//
// versions.json: { "latest": "0.1.0",
//                  "versions": [{ "version": "0.1.0" }],
//                  "next": true }
// Layout: latest is served at the root and at /v<version>/, the others at
// /v<version>/, and the development docs at /next/.
(() => {
  const meta = (name) => document.querySelector(`meta[name="${name}"]`)?.getAttribute('content');
  const current = meta('docs-version');
  if (!current) return;
  const base = meta('docs-base') ?? '';
  const channel = meta('docs-channel') ?? 'release';
  const key = channel === 'next' ? 'next' : current;
  const path = location.pathname.startsWith(`${base}/`) ? location.pathname.slice(base.length) : location.pathname;

  const compare = (a, b) => {
    const left = a.split('.').map(Number);
    const right = b.split('.').map(Number);
    for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
      const difference = (right[index] ?? 0) - (left[index] ?? 0);
      if (difference) return difference;
    }
    return 0;
  };

  fetch('/versions.json', { cache: 'no-cache' })
    .then((response) => (response.ok ? response.json() : Promise.reject(new Error(String(response.status)))))
    .then((manifest) => {
      const latest = manifest.latest;
      const releases = [...manifest.versions].sort((a, b) => compare(a.version, b.version));
      const baseFor = (version) => (version === 'next' ? '/next' : version === latest ? '' : `/v${version}`);
      const entries = [
        ...(manifest.next ? [{ key: 'next', label: 'next (development)' }] : []),
        ...releases.map((release) => ({ key: release.version, label: release.version === latest ? `${release.version} (latest)` : release.version })),
      ];

      const style = document.createElement('style');
      style.textContent = `
        .docs-version { display: inline-flex; align-items: center; gap: .4rem; font-size: var(--sl-text-sm); color: var(--sl-color-gray-2); }
        .docs-version select { font: inherit; color: var(--sl-color-text); background: var(--sl-color-bg-nav, transparent);
          border: 1px solid var(--sl-color-gray-5); border-radius: .4rem; padding: .25rem .5rem; cursor: pointer; }
        .docs-version-banner { margin: 0 0 1rem; padding: .75rem 1rem; border-inline-start: .25rem solid var(--sl-color-orange);
          background: var(--sl-color-orange-low); color: var(--sl-color-text); font-size: var(--sl-text-sm); }
        .docs-version-banner a { color: var(--sl-color-text-accent); font-weight: 600; }`;
      document.head.append(style);

      const navigate = async (version) => {
        const destination = baseFor(version);
        const candidate = `${destination}${path}`;
        let target = `${destination}/`;
        try { if ((await fetch(candidate, { method: 'HEAD' })).ok) target = `${candidate}${location.hash}`; } catch { /* keep the version root */ }
        location.assign(target);
      };
      const control = () => {
        const select = document.createElement('select');
        select.setAttribute('aria-label', 'Documentation version');
        for (const entry of entries) select.append(new Option(entry.label, entry.key, false, entry.key === key));
        select.addEventListener('change', () => navigate(select.value));
        const wrapper = document.createElement('div');
        wrapper.className = 'docs-version';
        wrapper.dataset.pagefindIgnore = '';
        wrapper.append(select);
        return wrapper;
      };
      document.querySelector('.right-group')?.prepend(control());
      document.querySelector('.mobile-preferences')?.prepend(control());

      let message = null;
      if (channel === 'next') {
        message = `These are the development docs for the <code>main</code> branch and may describe behaviour that is not released yet. The latest release is <a href="${baseFor(latest)}${path}">${latest}</a>.`;
      } else if (current !== latest) {
        message = `You are reading the documentation for ${current}, which is not the latest release. <a href="${baseFor(latest)}${path}">Read the latest, ${latest}.</a>`;
      }
      if (message) {
        const banner = document.createElement('div');
        banner.className = 'docs-version-banner';
        banner.setAttribute('role', 'note');
        banner.dataset.pagefindIgnore = '';
        banner.innerHTML = message;
        document.querySelector('main')?.prepend(banner);
      }
    })
    .catch(() => { /* no manifest (for example a local preview): leave the page as built */ });
})();
