/// <reference types="vite/client" />
declare module '*.vue' {
  import type { DefineComponent } from 'vue';
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const c: DefineComponent<Record<string, never>, Record<string, never>, any>;
  export default c;
}
