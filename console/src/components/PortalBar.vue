<template>
  <header class="bd-pbar">
    <div class="bd-plogo">
      <span class="bd-plogo__mark">
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none">
          <path d="M12 2l8 3v6c0 5-3.5 8.5-8 11-4.5-2.5-8-6-8-11V5l8-3z" fill="#fff" opacity=".95" />
          <path d="M9 12l2 2 4-4" stroke="#165DFF" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
      </span>
      <span class="bd-plogo__txt">{{ title }}</span>
    </div>
    <div class="bd-pbar__spacer" />
    <slot />
  </header>
</template>

<script setup lang="ts">
defineProps<{ title: string }>();
</script>

<style scoped>
.bd-pbar {
  height: 56px; background: #fff; border-bottom: 1px solid var(--bd-border);
  display: flex; align-items: center; padding: 0 24px; gap: 14px; position: sticky; top: 0; z-index: 10;
}
.bd-plogo { display: inline-flex; align-items: center; gap: 10px; }
.bd-plogo__mark {
  width: 30px; height: 30px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--bd-primary), var(--bd-primary-d));
}
.bd-plogo__txt { font-size: 14.5px; font-weight: 600; color: var(--bd-t1); }
.bd-pbar__spacer { flex: 1; }
</style>
