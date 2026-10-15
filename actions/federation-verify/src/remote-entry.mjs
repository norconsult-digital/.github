import { z } from 'zod';

// Structural validation for native-federation remoteEntry.json files.
// .loose() because the real artifact carries extra fields (outFileName,
// dev/prod entry maps, etc.) that are not contract-relevant.

const sharedEntrySchema = z.looseObject({
  packageName: z.string().min(1),
  requiredVersion: z.string().min(1),
  // The resolved build version. Deliberately unused by the diff rules —
  // it changes on every dependency patch bump without contract impact.
  version: z.string().optional(),
  singleton: z.boolean().default(false),
  strictVersion: z.boolean().default(false)
});

const exposesEntrySchema = z.looseObject({
  key: z.string().min(1)
});

export const remoteEntrySchema = z.looseObject({
  name: z.string().min(1),
  shared: z.array(sharedEntrySchema).default([]),
  exposes: z.array(exposesEntrySchema).default([])
});

/** @returns {z.infer<typeof remoteEntrySchema>} */
export function parseRemoteEntry(json, label) {
  const result = remoteEntrySchema.safeParse(json);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new Error(`${label} is not a valid remoteEntry.json:\n${issues}`);
  }
  return result.data;
}
