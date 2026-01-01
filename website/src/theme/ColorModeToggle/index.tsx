import React from 'react';
import {useColorMode} from '@docusaurus/theme-common';
import styles from './styles.module.css';

type ColorMode = 'light' | 'dark' | 'system';

function getStoredPreference(): ColorMode {
  if (typeof window === 'undefined') return 'system';
  return (localStorage.getItem('theme-preference') as ColorMode) || 'system';
}

function getSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

export default function ColorModeToggle(): JSX.Element {
  const {colorMode, setColorMode} = useColorMode();
  const [preference, setPreference] = React.useState<ColorMode>('system');

  React.useEffect(() => {
    setPreference(getStoredPreference());
  }, []);

  const handleChange = (newPreference: ColorMode) => {
    setPreference(newPreference);
    localStorage.setItem('theme-preference', newPreference);

    if (newPreference === 'system') {
      setColorMode(getSystemTheme());
    } else {
      setColorMode(newPreference);
    }
  };

  React.useEffect(() => {
    if (preference !== 'system') return;

    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    const handleSystemChange = (e: MediaQueryListEvent) => {
      setColorMode(e.matches ? 'dark' : 'light');
    };

    mediaQuery.addEventListener('change', handleSystemChange);
    return () => mediaQuery.removeEventListener('change', handleSystemChange);
  }, [preference, setColorMode]);

  return (
    <div className={styles.themeSwitcher}>
      <button
        className={preference === 'light' ? styles.active : ''}
        onClick={() => handleChange('light')}
        title="Light theme"
        aria-label="Light theme"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="5"/>
          <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/>
        </svg>
      </button>
      <button
        className={preference === 'dark' ? styles.active : ''}
        onClick={() => handleChange('dark')}
        title="Dark theme"
        aria-label="Dark theme"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
        </svg>
      </button>
      <button
        className={preference === 'system' ? styles.active : ''}
        onClick={() => handleChange('system')}
        title="System theme"
        aria-label="System theme"
      >
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="2" y="3" width="20" height="14" rx="2"/>
          <path d="M8 21h8M12 17v4"/>
        </svg>
      </button>
    </div>
  );
}
