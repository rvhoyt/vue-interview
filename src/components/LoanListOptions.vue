<script>
import api from '../services/api.ts'

export default {
  data() {
    return {
      loans: []
    }
  },
   created() {
      api.get('loangroups').then((resp) => this.loans = resp.data);
   }
}
</script>

<template>
  <pre>{{loans}}</pre>
</template>