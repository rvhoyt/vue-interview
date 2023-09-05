<script setup>
import { ref } from 'vue'
import api from '../services/api.ts'

const loans = ref([]);
api.get('loangroups').then((resp) => loans.value = resp.data);
</script>

<template>
  <pre>{{loans}}</pre>
</template>
