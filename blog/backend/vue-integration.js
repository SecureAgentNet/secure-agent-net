// =============================================================================
// SAN Blog – Vue.js Integration Examples
// =============================================================================
//
// These examples show how to integrate the PHP API with a Vue 3 application
// using the Composition API. The existing site uses Astro.js but these
// components are provided as a reference for Vue-based projects.
//
// API Base URL – update this to your Hetzner server:
//   const API_HOST = 'https://yourdomain.com/blog/backend/api';
//
// All endpoints return JSON with CORS headers enabled.
// =============================================================================

// ---------------------------------------------------------------------------
// 1. API Service (api.js) – centralized fetch wrapper
// ---------------------------------------------------------------------------

const API_HOST = import.meta.env.VITE_API_HOST || '/blog/backend/api';

const api = {
  async request(endpoint, options = {}) {
    const url = `${API_HOST}${endpoint}`;
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  getPosts(page = 1, limit = 12, filters = {}) {
    const params = new URLSearchParams({ page, limit, ...filters });
    return this.request(`/posts?${params}`);
  },

  getPost(slug) {
    return this.request(`/posts/${encodeURIComponent(slug)}`);
  },

  getCategories() {
    return this.request('/categories');
  },

  getTags() {
    return this.request('/tags');
  },

  getComments(postId) {
    return this.request(`/comments?post_id=${postId}`);
  },

  submitComment(data) {
    return this.request('/comments', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },
};

export default api;


// ---------------------------------------------------------------------------
// 2. BlogList.vue – displays paginated blog posts with category/tag filters
// ---------------------------------------------------------------------------
/*
<template>
  <div class="blog-list">
    <div class="filters">
      <select v-model="selectedCategory" @change="fetchPosts">
        <option value="">All Categories</option>
        <option v-for="cat in categories" :key="cat.slug" :value="cat.slug">
          {{ cat.name }} ({{ cat.post_count }})
        </option>
      </select>
      <select v-model="selectedTag" @change="fetchPosts">
        <option value="">All Tags</option>
        <option v-for="tag in tags" :key="tag.slug" :value="tag.slug">
          {{ tag.name }} ({{ tag.post_count }})
        </option>
      </select>
    </div>

    <div v-if="loading" class="loading">Loading...</div>

    <div v-else class="posts-grid">
      <article v-for="post in posts" :key="post.id" class="post-card">
        <img v-if="post.cover_image" :src="post.cover_image" :alt="post.title" />
        <h2>
          <router-link :to="`/blog/${post.slug}`">{{ post.title }}</router-link>
        </h2>
        <p class="summary">{{ post.summary }}</p>
        <div class="meta">
          <span>{{ post.author }}</span>
          <span>{{ formatDate(post.published_at) }}</span>
          <span>{{ post.read_time }} read</span>
        </div>
        <div class="tags">
          <span v-for="tag in post.tags" :key="tag.id" class="tag">
            #{{ tag.name }}
          </span>
        </div>
      </article>
    </div>

    <div class="pagination" v-if="totalPages > 1">
      <button
        v-for="p in totalPages"
        :key="p"
        :class="{ active: p === currentPage }"
        @click="goToPage(p)"
      >
        {{ p }}
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';
import api from './api.js';

const posts = ref([]);
const categories = ref([]);
const tags = ref([]);
const loading = ref(true);
const currentPage = ref(1);
const totalPages = ref(1);
const selectedCategory = ref('');
const selectedTag = ref('');

async function fetchPosts() {
  loading.value = true;
  try {
    const filters = {};
    if (selectedCategory.value) filters.category = selectedCategory.value;
    if (selectedTag.value) filters.tag = selectedTag.value;

    const result = await api.getPosts(currentPage.value, 12, filters);
    posts.value = result.data;
    totalPages.value = result.pagination.totalPages;
  } catch (err) {
    console.error('Failed to load posts:', err);
  } finally {
    loading.value = false;
  }
}

function goToPage(page) {
  currentPage.value = page;
  fetchPosts();
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

onMounted(async () => {
  try {
    const [catData, tagData] = await Promise.all([
      api.getCategories(),
      api.getTags(),
    ]);
    categories.value = catData;
    tags.value = tagData;
  } catch (err) {}
  fetchPosts();
});
</script>

<style scoped>
.posts-grid { display: grid; gap: 1.5rem; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); }
.post-card { border: 1px solid #e5e7eb; border-radius: 0.75rem; padding: 1.25rem; }
.tag { display: inline-block; background: #f3f4f6; padding: 0.15rem 0.5rem; border-radius: 0.25rem; font-size: 0.75rem; margin-right: 0.5rem; }
.pagination { display: flex; gap: 0.5rem; justify-content: center; margin-top: 2rem; }
.pagination button { padding: 0.5rem 1rem; border: 1px solid #d1d5db; border-radius: 0.375rem; cursor: pointer; }
.pagination button.active { background: #2563eb; color: white; border-color: #2563eb; }
</style>
*/


// ---------------------------------------------------------------------------
// 3. PostDetail.vue – single post with comments
// ---------------------------------------------------------------------------
/*
<template>
  <div class="post-detail" v-if="post">
    <h1>{{ post.title }}</h1>
    <div class="meta">
      <span>{{ post.author }}</span>
      <span>{{ post.read_time }} read</span>
      <span>{{ formatDate(post.published_at) }}</span>
    </div>
    <div v-if="post.summary" class="summary">{{ post.summary }}</div>
    <div class="body markdown-body" v-html="renderedBody"></div>

    <section class="comments">
      <h3>Comments ({{ comments.length }})</h3>
      <div v-for="c in comments" :key="c.id" class="comment">
        <strong>{{ c.author_name }}</strong>
        <time>{{ formatDate(c.created_at) }}</time>
        <p>{{ c.body }}</p>
      </div>

      <form @submit.prevent="submitComment" class="comment-form">
        <input v-model="newComment.author_name" placeholder="Your name" required />
        <input v-model="newComment.author_email" type="email" placeholder="Your email" required />
        <textarea v-model="newComment.body" placeholder="Write a comment..." required rows="3"></textarea>
        <button type="submit" :disabled="submitting">Submit</button>
        <p v-if="commentMsg" :class="commentMsg.type">{{ commentMsg.text }}</p>
      </form>
    </section>
  </div>
  <div v-else-if="error">{{ error }}</div>
</template>

<script setup>
import { ref, computed, onMounted } from 'vue';
import { marked } from 'marked';
import api from './api.js';

const props = defineProps({ slug: String });

const post = ref(null);
const comments = ref([]);
const error = ref('');
const submitting = ref(false);
const commentMsg = ref(null);

const newComment = ref({
  author_name: '',
  author_email: '',
  body: '',
});

const renderedBody = computed(() =>
  marked.parse(post.value?.body || post.value?.content || '')
);

async function loadPost() {
  try {
    post.value = await api.getPost(props.slug);
    comments.value = await api.getComments(post.value.id);
  } catch (err) {
    error.value = err.message;
  }
}

async function submitComment() {
  submitting.value = true;
  commentMsg.value = null;
  try {
    await api.submitComment({
      post_id: post.value.id,
      ...newComment.value,
    });
    newComment.value = { author_name: '', author_email: '', body: '' };
    commentMsg.value = { type: 'success', text: 'Comment submitted!' };
    comments.value = await api.getComments(post.value.id);
  } catch (err) {
    commentMsg.value = { type: 'error', text: err.message };
  } finally {
    submitting.value = false;
  }
}

function formatDate(dateStr) {
  return new Date(dateStr).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });
}

onMounted(loadPost);
</script>
*/


// ---------------------------------------------------------------------------
// 4. Vue Router Setup Example (router.js)
// ---------------------------------------------------------------------------
/*
import { createRouter, createWebHistory } from 'vue-router';
import BlogList from './components/BlogList.vue';
import PostDetail from './components/PostDetail.vue';

const routes = [
  { path: '/blog', component: BlogList },
  { path: '/blog/:slug', component: PostDetail, props: true },
];

export default createRouter({
  history: createWebHistory(),
  routes,
});
*/


// ---------------------------------------------------------------------------
// 5. Axios alternative for the API service
// ---------------------------------------------------------------------------
/*
import axios from 'axios';

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_HOST || '/blog/backend/api',
  headers: { 'Content-Type': 'application/json' },
});

export const blogAPI = {
  getPosts(filters = {}) {
    return apiClient.get('/posts', { params: filters }).then(r => r.data);
  },
  getPost(slug) {
    return apiClient.get(`/posts/${slug}`).then(r => r.data);
  },
  getCategories() {
    return apiClient.get('/categories').then(r => r.data);
  },
  getTags() {
    return apiClient.get('/tags').then(r => r.data);
  },
  getComments(postId) {
    return apiClient.get('/comments', { params: { post_id: postId } }).then(r => r.data);
  },
  submitComment(data) {
    return apiClient.post('/comments', data).then(r => r.data);
  },
};
*/
