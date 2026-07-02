import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

const blog = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/blog' }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    authors: z.array(z.string()),
    date: z.coerce.date(),
    readTime: z.string(),
    tags: z.array(z.string()).default([]),
    accent: z.enum(['text-primary', 'text-secondary', 'text-tertiary-container']).default('text-primary'),
    featured: z.boolean().default(false),
  }),
});

export const collections = { blog };