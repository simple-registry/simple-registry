export type ThemePreference = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'theme-preference';

let preference: ThemePreference = $state('system');
let resolvedTheme: 'light' | 'dark' = $state('dark');

function getSystemTheme(): 'light' | 'dark' {
	if (typeof window === 'undefined') return 'dark';
	return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function applyTheme(theme: 'light' | 'dark') {
	if (typeof document === 'undefined') return;
	document.documentElement.setAttribute('data-theme', theme);
	resolvedTheme = theme;
}

function updateTheme() {
	const theme = preference === 'system' ? getSystemTheme() : preference;
	applyTheme(theme);
}

export function initTheme() {
	if (typeof window === 'undefined') return;

	const stored = localStorage.getItem(STORAGE_KEY) as ThemePreference | null;
	if (stored && ['light', 'dark', 'system'].includes(stored)) {
		preference = stored;
	}

	updateTheme();

	window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
		if (preference === 'system') {
			updateTheme();
		}
	});
}

export function setTheme(newPreference: ThemePreference) {
	preference = newPreference;
	localStorage.setItem(STORAGE_KEY, newPreference);
	updateTheme();
}

export function getThemePreference(): ThemePreference {
	return preference;
}

export function getResolvedTheme(): 'light' | 'dark' {
	return resolvedTheme;
}
