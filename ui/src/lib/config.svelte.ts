interface UiConfig {
	name: string;
}

let config: UiConfig = $state({ name: 'angos' });
let loaded = $state(false);

export async function loadConfig(): Promise<void> {
	if (loaded) return;

	try {
		const response = await fetch('/_ui/config');
		if (response.ok) {
			const data: UiConfig = await response.json();
			config = data;
		}
	} catch {
		// Use defaults on error
	}
	loaded = true;
}

export function getRegistryName(): string {
	return config.name;
}
