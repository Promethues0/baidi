import { defineStore } from 'pinia';
import { ref } from 'vue';

export const useUiStore = defineStore('ui', () => {
  const theme = ref<'light' | 'dark'>((localStorage.getItem('zl-theme') as 'light' | 'dark') || 'light');
  const collapsed = ref(false);

  function applyTheme() {
    document.body.setAttribute('arco-theme', theme.value);
    document.documentElement.setAttribute('data-theme', theme.value);
  }
  function toggleTheme() {
    theme.value = theme.value === 'dark' ? 'light' : 'dark';
    localStorage.setItem('zl-theme', theme.value);
    applyTheme();
  }
  applyTheme();

  return { theme, collapsed, toggleTheme };
});
