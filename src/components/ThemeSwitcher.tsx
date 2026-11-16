import React, { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { ThemeModePreference } from '../types';

export const ThemeSwitcher: React.FC<{ className?: string }> = ({ className = '' }) => {
  const { preferences, updateStudentPreferences } = useAuth();
  const [systemPrefersDark, setSystemPrefersDark] = useState<boolean>(() =>
    typeof window !== 'undefined' && window.matchMedia
      ? window.matchMedia('(prefers-color-scheme: dark)').matches
      : false
  );

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const sync = () => setSystemPrefersDark(mq.matches);
    sync();
    mq.addEventListener('change', sync);
    return () => mq.removeEventListener('change', sync);
  }, []);

  const currentTheme = preferences.theme || 'light';
  const isDarkResolved =
    currentTheme === 'dark' || (currentTheme === 'auto' && systemPrefersDark);
  const currentLabel =
    currentTheme === 'auto'
      ? 'Automático'
      : currentTheme === 'dark'
        ? 'Modo Escuro'
        : 'Modo Claro';
  const nextTheme: ThemeModePreference = isDarkResolved ? 'light' : 'dark';
  const nextLabel = nextTheme === 'dark' ? 'Modo Escuro' : 'Modo Claro';

  const handleToggleTheme = () => {
    void updateStudentPreferences({ theme: nextTheme });
  };

  return (
    <div className={`relative ${className}`}>
      <button
        type="button"
        onClick={handleToggleTheme}
        aria-label={`Alternar tema da plataforma (atual: ${currentLabel} — toque para ${nextLabel})`}
        aria-pressed={isDarkResolved}
        title={`Tema atual: ${currentLabel}. Toque para alternar para ${nextLabel}`}
        className="relative min-w-[36px] min-h-[36px] sm:min-w-[38px] sm:min-h-[38px] px-2 sm:px-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/80 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 inline-flex items-center justify-center active:scale-95 transition-all"
      >
        {isDarkResolved ? (
          <Moon className="w-4 h-4 text-emerald-400" />
        ) : (
          <Sun className="w-4 h-4 text-amber-500" />
        )}
      </button>
    </div>
  );
};
